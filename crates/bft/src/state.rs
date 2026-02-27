//! BFT consensus state machine.
//!
//! This module implements the BFT consensus state machine
//! as a synchronous, event-driven model.
//!
//! # Data Availability Guarantee
//!
//! Validators only vote for blocks after receiving ALL transaction and certificate
//! data. This is enforced in [`BftState::on_block_header`] which checks `is_complete()`
//! before voting. Incomplete blocks wait for data via gossip or fetch.
//!
//! This provides a strong DA guarantee: if a QC forms, at least 2f+1 validators have
//! the complete block data, making it recoverable from any honest validator in that set.

use hyperscale_core::{Action, ProtocolEvent, TimerId};

/// BFT statistics for monitoring.
#[derive(Clone, Copy, Debug, Default)]
pub struct BftStats {
    /// Total number of view changes (round advances due to timeout).
    pub view_changes: u64,
    /// Current round within the current height.
    pub current_round: u64,
    /// Current committed height.
    pub committed_height: u64,
}

/// Index type for simulation-only node routing.
/// Production uses ValidatorId (from message signatures) and PeerId (libp2p).
pub type NodeIndex = u32;
use hyperscale_types::{
    state_provision_message, Block, BlockHeader, BlockHeight, BlockVote, Bls12381G1PrivateKey,
    Bls12381G1PublicKey, CommitmentProof, Hash, QuorumCertificate, ReadyTransactions,
    RoutableTransaction, ShardGroupId, Topology, TransactionAbort, TransactionCertificate,
    TransactionDefer, ValidatorId, VotePower,
};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, instrument, trace, warn};

use crate::config::BftConfig;
use crate::pending::PendingBlock;
use crate::vote_set::VoteSet;

/// State recovered from storage on startup.
///
/// Passed to `BftState::new()` to restore consensus state after a crash/restart.
/// For a fresh start, use `RecoveredState::default()`.
#[derive(Debug, Clone, Default)]
pub struct RecoveredState {
    /// Our own votes, indexed by height → (block_hash, round).
    /// **BFT Safety Critical**: Prevents equivocation after restart.
    pub voted_heights: HashMap<u64, (Hash, u64)>,

    /// Last committed block height.
    pub committed_height: u64,

    /// Last committed block hash (None for fresh start).
    pub committed_hash: Option<Hash>,

    /// Latest QC (certifies the highest certified block).
    pub latest_qc: Option<QuorumCertificate>,

    /// Last committed JMT state (version, root_hash).
    ///
    /// This is the actual JMT state from storage at startup. Used to ensure
    /// block headers derive state_version from actual committed state, not
    /// from the hardcoded genesis (0, Hash::ZERO).
    ///
    /// If not provided (None), defaults to (0, Hash::ZERO) for fresh start.
    pub jmt_state: Option<(u64, Hash)>,
}

/// Block header pending QC signature verification.
///
/// When we receive a block header with a non-genesis parent_qc, we need to
/// verify the QC's aggregated BLS signature before voting. This struct
/// tracks the block header while waiting for verification.
#[derive(Debug, Clone)]
struct PendingQcVerification {
    /// The block header we're considering voting on.
    header: BlockHeader,
}

/// Synced block pending QC signature verification.
///
/// When we receive a synced block, we must verify its QC signature before
/// applying it to our state.
#[derive(Debug, Clone)]
struct PendingSyncedBlockVerification {
    /// The synced block awaiting QC verification.
    block: Block,
    /// The QC that certifies this block.
    qc: QuorumCertificate,
    /// Whether the QC signature has been verified.
    verified: bool,
}

/// Tracks pending CycleProof verifications for a block.
///
/// When a block contains deferrals with CycleProofs, we need to verify each
/// proof's BLS signature before voting on the block. This struct tracks the
/// verification progress for a single block.
#[derive(Debug, Clone)]
struct PendingCycleProofVerifications {
    /// Total number of deferrals needing verification.
    total: usize,
    /// Number of deferrals verified so far.
    verified: usize,
    /// Whether all verified proofs are valid so far.
    all_valid: bool,
}

/// Pending state root verification waiting for JMT to be ready.
///
/// When a block arrives but its parent block's state hasn't been committed to
/// the JMT yet, we queue the verification here. Once StateCommitComplete arrives
/// with a root matching required_root, we can proceed with verification.
#[derive(Debug, Clone)]
struct PendingStateRootVerification {
    /// The state root of the parent block. Verification waits until local JMT
    /// reaches this root, ensuring proposer and verifier compute from same base.
    required_root: Hash,
    /// The state root claimed by the proposer (to verify against).
    expected_root: Hash,
    /// The certificates to commit. State writes are extracted from these.
    /// Also used to pre-build the RocksDB WriteBatch during verification
    /// for efficient single-fsync commit later.
    certificates: Vec<std::sync::Arc<hyperscale_types::TransactionCertificate>>,
}

/// Tracks in-flight proposal for correlating `Event::ProposalBuilt` callback.
#[derive(Debug, Clone)]
struct PendingProposal {
    height: BlockHeight,
    round: u64,
}

/// BFT consensus state machine.
///
/// Handles block proposal, voting, QC formation, commitment, and view changes.
/// This is a synchronous implementation of BFT consensus.
///
/// # State Machine Flow
///
/// 1. **Proposal Timer** → If proposer, build and broadcast block header
/// 2. **Block Header Received** → Validate, track pending, vote if valid
/// 3. **Block Vote Received** → Collect votes, form QC when quorum reached
/// 4. **QC Formed** → Update chain state, commit if ready (two-chain rule)
/// 5. **View Change Timer** → Initiate view change if no progress
pub struct BftState {
    // ═══════════════════════════════════════════════════════════════════════════
    // Identity
    // ═══════════════════════════════════════════════════════════════════════════
    /// This node's index (deterministic ordering).
    node_index: NodeIndex,

    /// Signing key for votes and proposals.
    signing_key: Bls12381G1PrivateKey,

    /// Network topology (single source of truth for committee/shard info).
    topology: Arc<dyn Topology>,

    /// Shard group identifier for vote signature domain separation.
    /// Prevents cross-shard replay attacks when validators participate in multiple shards.
    shard_group: ShardGroupId,

    // ═══════════════════════════════════════════════════════════════════════════
    // Chain State
    // ═══════════════════════════════════════════════════════════════════════════
    /// Current view/round number.
    view: u64,

    /// View number at the start of the current height.
    ///
    /// Used for linear backoff calculation: `rounds_at_height = view - view_at_height_start`.
    /// Reset to `view` when `committed_height` advances (height transition).
    ///
    /// This enables Tendermint-style timeout backoff where the view change timeout
    /// increases linearly with each failed round at the same height, preventing
    /// synchronized timeout storms across validators.
    view_at_height_start: u64,

    /// Latest committed block height.
    committed_height: u64,

    /// Hash of the latest committed block.
    committed_hash: Hash,

    /// Latest QC (certifies the latest certified block).
    latest_qc: Option<QuorumCertificate>,

    /// Genesis block (needed for bootstrapping).
    genesis_block: Option<Block>,

    // ═══════════════════════════════════════════════════════════════════════════
    // Pending State
    // ═══════════════════════════════════════════════════════════════════════════
    /// Pending blocks being assembled (hash -> pending block).
    pending_blocks: HashMap<Hash, PendingBlock>,

    /// Tracks when each pending block was created (hash -> creation time).
    /// Used for fetch timeout tracking - we delay fetching missing data to allow
    /// gossip and local certificate creation time to fill in missing data first.
    pending_block_created_at: HashMap<Hash, Duration>,

    /// Vote sets for blocks (hash -> vote set).
    vote_sets: HashMap<Hash, VoteSet>,

    /// Vote locking: tracks which block hash we voted for at each height.
    /// Critical for BFT safety - prevents voting for conflicting blocks at the same height
    /// and round. The lock may be released across rounds on timeout (see `advance_round`)
    /// or when a QC proves the lock is irrelevant (see `maybe_unlock_for_qc`).
    ///
    /// Key: height, Value: (block_hash, round)
    /// We also track the round to allow re-voting for the SAME block in a later round
    /// (which is safe), while preventing votes for DIFFERENT blocks at the same height and round.
    voted_heights: HashMap<u64, (Hash, u64)>,

    /// Tracks which block each validator has voted for at each height.
    /// Key: (height, validator_id), Value: block_hash
    ///
    /// This prevents Byzantine validators from voting for multiple blocks at the same height
    /// AND round across different VoteSets. With HotStuff-2 style voting, validators can
    /// legitimately vote for different blocks at the same height if they're at different rounds
    /// (due to unlock on round advancement). True equivocation is voting for different blocks
    /// at the SAME height AND round.
    ///
    /// Maps (height, voter) -> (block_hash, round) so we can distinguish legitimate revotes
    /// (different round) from Byzantine equivocation (same round, different block).
    received_votes_by_height: HashMap<(u64, ValidatorId), (Hash, u64)>,

    /// Blocks that have been certified (have QC) but not yet committed.
    /// Maps block_hash -> (Block, QC).
    certified_blocks: HashMap<Hash, (Block, QuorumCertificate)>,

    /// Block headers pending QC signature verification.
    /// Maps block_hash -> pending verification info.
    /// When we receive a block header with non-genesis parent_qc, we must verify
    /// the QC's aggregated BLS signature before voting on the block.
    pending_qc_verifications: HashMap<Hash, PendingQcVerification>,

    /// Synced blocks pending QC signature verification.
    /// Maps block_hash -> pending synced block info.
    /// When we receive a synced block, we must verify its QC's signature before applying.
    pending_synced_block_verifications: HashMap<Hash, PendingSyncedBlockVerification>,

    /// Blocks waiting for CycleProof verification before voting.
    /// Maps block_hash -> pending verification state.
    /// When a block contains deferrals with CycleProofs, we must verify each proof's
    /// BLS signature before voting. This tracks the verification progress.
    pending_cycle_proof_verifications: HashMap<Hash, PendingCycleProofVerifications>,

    /// Blocks where state root verification is currently in-flight (being computed).
    /// When verification completes, the block hash is moved to verified_state_roots
    /// (if valid) or the block is rejected (if invalid).
    state_root_verifications_in_flight: HashSet<Hash>,

    /// Blocks waiting for JMT to reach the required version before verification can start.
    /// When a block arrives but the JMT hasn't committed the parent block's state yet,
    /// we queue it here. When StateCommitComplete arrives, we check if any queued
    /// verifications can now proceed.
    pending_state_root_verifications: HashMap<Hash, PendingStateRootVerification>,

    /// Last committed JMT state (version, root). Updated via StateCommitComplete.
    ///
    /// Used to check if JMT is ready for state root verification.
    /// NOT used for block header state_version (use `last_chain_committed_state_version`).
    last_committed_jmt_state: (u64, Hash),

    /// State version from the most recently COMMITTED block's header.
    ///
    /// Updated SYNCHRONOUSLY when blocks commit (in commit_block_and_buffered).
    /// This tracks the state_version from the COMMITTED chain, which is what
    /// verifiers can actually reach via JMT commits.
    ///
    /// CRITICAL: This must be used as the base for proposals, NOT the parent
    /// block's state_version from the QC chain. The QC chain can grow speculatively
    /// (blocks get certified but not committed during view changes), causing
    /// state_version to increment without JMT advancing. Using committed state
    /// ensures verifiers can always reach the required_base_version.
    ///
    /// Example of the bug this prevents:
    /// - Block A (height 10) commits with 5 certs, state_version = 9
    /// - Block B (height 11) gets QC with 40 certs, state_version = 49, but view changes
    /// - Block C (height 12) extends B's QC with 10 certs, state_version = 59
    /// - Verifier needs JMT at 49 to verify C, but JMT is at 9 (only A committed)
    /// - DEADLOCK!
    ///
    /// Fix: Use committed state_version (9) as base, not parent's speculative version.
    last_chain_committed_state_version: u64,

    /// Blocks with verified state roots (prevents re-verification).
    verified_state_roots: HashSet<Hash>,

    /// Blocks with verified transaction roots (prevents re-verification).
    verified_transaction_roots: HashSet<Hash>,

    /// Blocks where transaction root verification is currently in-flight.
    transaction_root_verifications_in_flight: HashSet<Hash>,

    /// Blocks with verified CycleProofs (prevents re-verification).
    verified_cycle_proofs: HashSet<Hash>,

    /// Cache of already-verified QC signatures.
    /// Maps QC's block_hash (the block the QC certifies) -> height.
    /// When we see the same QC in multiple block headers (e.g., during view changes
    /// where multiple proposals at the same height share the same parent_qc), we can
    /// skip re-verification and proceed directly to voting.
    /// The height is stored to enable cleanup of old entries.
    verified_qcs: HashMap<Hash, u64>,

    /// Buffered out-of-order synced blocks waiting for earlier blocks.
    /// Maps height -> (Block, QC).
    /// When we receive a synced block for height N but we're still waiting for earlier
    /// heights, we buffer it here. Once the earlier blocks are processed, we pull from
    /// this buffer and submit for verification.
    buffered_synced_blocks: std::collections::BTreeMap<u64, (Block, QuorumCertificate)>,

    /// Buffered commits waiting for earlier blocks to commit first.
    /// Maps height -> (block_hash, QC).
    /// When we receive a BlockReadyToCommit for height N but we're still at committed_height < N-1,
    /// we buffer it here and process it once the earlier blocks are committed.
    /// This handles out-of-order commit events caused by parallel signature verification.
    pending_commits: std::collections::BTreeMap<u64, (Hash, QuorumCertificate)>,

    /// Commits waiting for block data (transactions/certificates) to arrive.
    /// Maps block_hash -> (height, QC).
    /// When BlockReadyToCommit fires but the block isn't complete yet (still fetching
    /// transactions), we buffer the commit here and retry when the data arrives.
    pending_commits_awaiting_data: HashMap<Hash, (u64, QuorumCertificate)>,

    /// In-flight proposal awaiting `Event::ProposalBuilt` callback.
    pending_proposal: Option<PendingProposal>,

    // ═══════════════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════════════
    config: BftConfig,

    // ═══════════════════════════════════════════════════════════════════════════
    // Time
    // ═══════════════════════════════════════════════════════════════════════════
    /// Current time (set by runner before each handle call).
    now: Duration,

    /// Timestamp of the last block proposal we made.
    /// Used for rate limiting block production via min_block_interval.
    last_proposal_time: Duration,

    /// Time of last leader activity (for round timeout detection).
    /// Reset when we see leader activity (proposal, header receipt, QC, commit).
    last_leader_activity: Duration,

    /// Last (height, round) for which we reset the leader activity timer on header receipt.
    /// Prevents a Byzantine leader from spamming headers to delay view changes.
    /// We only reset once per (height, round) from the leader.
    last_header_reset: Option<(u64, u64)>,

    // ═══════════════════════════════════════════════════════════════════════════
    // Sync State
    // ═══════════════════════════════════════════════════════════════════════════
    /// Whether we are currently syncing (catching up to the network).
    /// When syncing, we propose empty blocks instead of skipping our turn,
    /// and view changes are suppressed since we're intentionally behind.
    syncing: bool,

    // ═══════════════════════════════════════════════════════════════════════════
    // Statistics
    // ═══════════════════════════════════════════════════════════════════════════
    /// Total number of view changes (round advances due to timeout).
    view_changes: u64,
}

impl std::fmt::Debug for BftState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BftState")
            .field("node_index", &self.node_index)
            .field("validator_id", &self.topology.local_validator_id())
            .field("shard", &self.topology.local_shard())
            .field("committee_size", &self.topology.local_committee_size())
            .field("view", &self.view)
            .field("committed_height", &self.committed_height)
            .field("pending_blocks", &self.pending_blocks.len())
            .field("vote_sets", &self.vote_sets.len())
            .finish()
    }
}

impl BftState {
    /// Create a new BFT state machine.
    ///
    /// # Arguments
    ///
    /// * `node_index` - Deterministic node index for ordering
    /// * `signing_key` - Key for signing votes and proposals
    /// * `topology` - Network topology (single source of truth)
    /// * `config` - BFT configuration
    /// * `recovered` - State recovered from storage. Use `RecoveredState::default()` for fresh start.
    pub fn new(
        node_index: NodeIndex,
        signing_key: Bls12381G1PrivateKey,
        topology: Arc<dyn Topology>,
        config: BftConfig,
        recovered: RecoveredState,
    ) -> Self {
        // Get shard group for vote signature domain separation
        let shard_group = topology.local_shard();

        // Filter out votes for heights at or below committed height (stale votes from storage)
        let voted_heights: HashMap<u64, (Hash, u64)> = recovered
            .voted_heights
            .into_iter()
            .filter(|(height, _)| *height > recovered.committed_height)
            .collect();

        Self {
            node_index,
            signing_key,
            shard_group,
            topology,
            view: 0,
            view_at_height_start: 0,
            committed_height: recovered.committed_height,
            committed_hash: recovered
                .committed_hash
                .unwrap_or(Hash::from_bytes(&[0u8; 32])),
            latest_qc: recovered.latest_qc,
            genesis_block: None,
            pending_blocks: HashMap::new(),
            pending_block_created_at: HashMap::new(),
            vote_sets: HashMap::new(),
            voted_heights,
            received_votes_by_height: HashMap::new(),
            certified_blocks: HashMap::new(),
            pending_qc_verifications: HashMap::new(),
            pending_synced_block_verifications: HashMap::new(),
            pending_cycle_proof_verifications: HashMap::new(),
            state_root_verifications_in_flight: HashSet::new(),
            pending_state_root_verifications: HashMap::new(),
            last_committed_jmt_state: recovered.jmt_state.unwrap_or((0, Hash::ZERO)),
            // Chain-committed state starts at the JMT state (they're in sync at startup)
            // This will be updated when blocks commit via 2-chain rule.
            last_chain_committed_state_version: recovered.jmt_state.map(|(v, _)| v).unwrap_or(0),
            verified_state_roots: HashSet::new(),
            verified_transaction_roots: HashSet::new(),
            transaction_root_verifications_in_flight: HashSet::new(),
            verified_cycle_proofs: HashSet::new(),
            verified_qcs: HashMap::new(),
            buffered_synced_blocks: std::collections::BTreeMap::new(),
            pending_commits: std::collections::BTreeMap::new(),
            pending_commits_awaiting_data: HashMap::new(),
            pending_proposal: None,
            config,
            now: Duration::ZERO,
            last_proposal_time: Duration::ZERO,
            last_leader_activity: Duration::ZERO,
            last_header_reset: None,
            syncing: false,
            view_changes: 0,
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Topology Accessors
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get the local validator ID.
    fn validator_id(&self) -> ValidatorId {
        self.topology.local_validator_id()
    }

    /// Get the local shard.
    fn local_shard(&self) -> ShardGroupId {
        self.topology.local_shard()
    }

    /// Get the local committee.
    fn committee(&self) -> Cow<'_, [ValidatorId]> {
        self.topology.local_committee()
    }

    /// Get the total voting power.
    fn total_voting_power(&self) -> u64 {
        self.topology.local_voting_power()
    }

    /// Get voting power for a validator.
    fn voting_power(&self, validator_id: ValidatorId) -> u64 {
        self.topology.voting_power(validator_id).unwrap_or(0)
    }

    /// Get public key for a validator.
    fn public_key(&self, validator_id: ValidatorId) -> Option<Bls12381G1PublicKey> {
        self.topology.public_key(validator_id)
    }

    /// Check if we have quorum.
    #[allow(dead_code)]
    fn has_quorum(&self, voting_power: u64) -> bool {
        self.topology.local_has_quorum(voting_power)
    }

    /// Get proposer for height and round.
    fn proposer_for(&self, height: u64, round: u64) -> ValidatorId {
        self.topology.proposer_for(height, round)
    }

    /// Check if we should propose.
    fn should_propose(&self, height: u64, round: u64) -> bool {
        self.topology.should_propose(height, round)
    }

    /// Get committee index for a validator.
    fn committee_index(&self, validator_id: ValidatorId) -> Option<usize> {
        self.topology.local_committee_index(validator_id)
    }

    /// Get the chain-committed state version.
    ///
    /// This returns the state_version from the most recently COMMITTED block.
    /// Updated synchronously when blocks commit (in commit_block_and_buffered).
    ///
    /// CRITICAL: This must be used as the base for proposals with certificates.
    /// Using the parent block's state_version from the QC chain would cause
    /// deadlocks because the QC chain can grow speculatively during view changes
    /// while JMT only advances when blocks actually commit.
    ///
    /// NodeStateMachine must use this same value when computing state_root.
    pub fn get_chain_committed_state_version(&self) -> u64 {
        self.last_chain_committed_state_version
    }

    /// Get the local JMT state (version, root).
    ///
    /// This returns the actual JMT state from local async certificate commits.
    /// Different validators may have different values due to commit timing.
    ///
    /// Used by:
    /// - Verifiers to check if JMT is ready for state root verification
    /// - Fallback/sync blocks to get current root when no certs
    fn get_local_jmt_state(&self) -> (u64, Hash) {
        self.last_committed_jmt_state
    }

    /// Get a block by its hash.
    ///
    /// Looks up the block in certified_blocks, pending_blocks, or genesis.
    /// Used to walk the QC chain when computing state_version for proposals.
    fn get_block_by_hash(&self, block_hash: Hash) -> Option<Block> {
        if let Some((block, _)) = self.certified_blocks.get(&block_hash) {
            return Some(block.clone());
        }

        if let Some(pending) = self.pending_blocks.get(&block_hash) {
            if let Some(block) = pending.block() {
                return Some((*block).clone());
            }
        }

        if let Some(genesis) = &self.genesis_block {
            if genesis.hash() == block_hash {
                return Some(genesis.clone());
            }
        }

        None
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Time Management
    // ═══════════════════════════════════════════════════════════════════════════

    /// Set the current time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Sync State Management
    // ═══════════════════════════════════════════════════════════════════════════

    /// Set whether this validator is currently syncing.
    ///
    /// When syncing:
    /// - Proposer will create empty "sync blocks" instead of skipping their turn
    /// - View changes are suppressed (we're intentionally behind)
    fn set_syncing(&mut self, syncing: bool) {
        if syncing && !self.syncing {
            info!(
                validator = ?self.validator_id(),
                "Entering sync mode - will propose empty blocks if selected"
            );
        } else if !syncing && self.syncing {
            info!(
                validator = ?self.validator_id(),
                "Exiting sync mode - resuming normal block production"
            );
            // Reset leader activity timeout since we've caught up
            self.last_leader_activity = self.now;
        }
        self.syncing = syncing;
    }

    /// Check if this validator is currently syncing.
    pub fn is_syncing(&self) -> bool {
        self.syncing
    }

    /// Start syncing to catch up to the network.
    ///
    /// This is the single entry point for initiating sync. It:
    /// 1. Sets the syncing flag immediately (enables sync block proposals, suppresses fetches)
    /// 2. Returns the StartSync action for the runner to begin fetching blocks
    ///
    /// Setting the syncing flag immediately (rather than waiting for the first synced block)
    /// ensures that:
    /// - `check_pending_block_fetches()` stops emitting fetch requests that would compete with sync
    /// - Proposers create empty sync blocks instead of full blocks
    /// - The state machine accurately reflects that we're waiting for sync data
    ///
    /// The syncing flag will be cleared when `Event::SyncComplete` arrives.
    fn start_sync(&mut self, target_height: u64, target_hash: Hash) -> Vec<Action> {
        // Don't restart sync if we're already syncing
        // The runner's SyncManager handles target updates internally
        if self.syncing {
            debug!(
                validator = ?self.validator_id(),
                target_height,
                "Already syncing, skipping duplicate start_sync"
            );
            return vec![];
        }

        info!(
            validator = ?self.validator_id(),
            target_height,
            target_hash = ?target_hash,
            committed_height = self.committed_height,
            "Starting sync - setting syncing flag and requesting blocks"
        );

        // Set syncing flag immediately - this:
        // - Enables sync block proposals if we're the proposer
        // - Suppresses fetch requests (check_pending_block_fetches returns empty)
        // - Signals to other code that we're catching up
        self.set_syncing(true);

        vec![Action::StartSync {
            target_height,
            target_hash,
        }]
    }

    /// Handle a synced block ready to apply (from runner via Event::SyncBlockReadyToApply).
    pub fn on_sync_block_ready_to_apply(
        &mut self,
        block: Block,
        qc: QuorumCertificate,
    ) -> Vec<Action> {
        let block_height = block.header.height.0;

        // Ignore stale blocks that have already been committed.
        // Late-arriving sync blocks can arrive after sync completes.
        if block_height <= self.committed_height {
            debug!(
                validator = ?self.validator_id(),
                block_height,
                committed_height = self.committed_height,
                "Ignoring stale synced block - already committed"
            );
            return vec![];
        }

        self.on_synced_block_ready(block, qc)
    }

    /// Handle sync complete (from runner via Event::SyncComplete).
    ///
    /// Re-enables normal block proposals and view changes.
    /// Also triggers fetch requests for any pending blocks that still need data,
    /// since fetching was suppressed during sync.
    pub fn on_sync_complete(&mut self) -> Vec<Action> {
        info!(
            validator = ?self.validator_id(),
            "Sync complete, resuming normal consensus"
        );
        self.set_syncing(false);

        // Resume fetching for any pending blocks that still need data.
        // During sync, check_pending_block_fetches() returns empty because we
        // don't want to compete with sync for network resources. Now that sync
        // is done, we need to fetch any missing transactions/certificates.
        self.check_pending_block_fetches()
    }

    /// Record leader activity (resets the view change timeout).
    ///
    /// Called when we observe leader activity:
    /// - We propose a block
    /// - A QC forms
    /// - A block commits
    /// - We receive a valid header (rate-limited per height/round)
    fn record_leader_activity(&mut self) {
        self.last_leader_activity = self.now;
    }

    /// Record leader activity from receiving a block header.
    ///
    /// Rate-limited to once per (height, round) to prevent a Byzantine leader
    /// from spamming headers with different hashes to delay view changes.
    fn record_header_activity(&mut self, height: u64, round: u64) {
        let header_key = (height, round);
        if self.last_header_reset != Some(header_key) {
            self.last_leader_activity = self.now;
            self.last_header_reset = Some(header_key);
        }
    }

    /// Compute the current view change timeout with linear backoff.
    ///
    /// The timeout increases linearly with each round at the current height:
    /// `timeout = min(base + increment * rounds_at_height, max_timeout)`
    ///
    /// # Global Agreement
    ///
    /// Validators implicitly agree on the backoff because:
    /// 1. Round numbers are embedded in block headers and QCs
    /// 2. View sync keeps validators aligned on round numbers
    /// 3. All validators use the same formula to compute timeout
    ///
    /// When a validator receives a header or QC at round R, they know R rounds
    /// have been attempted, and can compute the same timeout as the proposer.
    fn current_view_change_timeout(&self) -> Duration {
        let base = self.config.view_change_timeout;
        let increment = self.config.view_change_timeout_increment;

        // Rounds attempted at current height (saturating to handle edge cases)
        let rounds_at_height = self.view.saturating_sub(self.view_at_height_start);

        // Linear backoff: base + increment * rounds
        let timeout = base + increment * rounds_at_height as u32;

        // Apply optional cap
        match self.config.view_change_timeout_max {
            Some(max) => timeout.min(max),
            None => timeout,
        }
    }

    /// Check if we should advance the round due to timeout.
    ///
    /// Returns true if the leader has been inactive for longer than the
    /// current timeout (which increases with each failed round at this height).
    ///
    /// View changes should only happen when the leader fails to propose,
    /// not just because vote aggregation is slow.
    ///
    /// Note: Syncing nodes DO participate in view changes. They receive headers
    /// from the network at the current height/round and need to help advance
    /// the view if the leader fails. When a syncing node becomes the proposer
    /// after a view change, they propose an empty sync block.
    fn should_advance_round(&self) -> bool {
        let timeout = self.current_view_change_timeout();
        self.now.saturating_sub(self.last_leader_activity) >= timeout
    }

    /// Check for round timeout and advance if needed.
    ///
    /// This should be called before processing the proposal timer.
    /// Returns actions for view change if timeout triggered, or empty vec if not.
    ///
    /// If a view change occurs, the caller should NOT proceed to call
    /// `on_proposal_timer` in the same event handling cycle.
    pub fn check_round_timeout(&mut self) -> Option<Vec<Action>> {
        if !self.should_advance_round() {
            return None;
        }

        // Reset the timeout so we don't immediately trigger another view change.
        self.last_leader_activity = self.now;
        // Clear the header reset tracker since we're changing rounds
        self.last_header_reset = None;

        let timeout = self.current_view_change_timeout();
        let rounds_at_height = self.view.saturating_sub(self.view_at_height_start);

        info!(
            validator = ?self.validator_id(),
            view = self.view,
            rounds_at_height = rounds_at_height,
            timeout_ms = timeout.as_millis(),
            "Round timeout - advancing round (implicit view change)"
        );

        Some(self.advance_round())
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Signature Message Construction
    // ═══════════════════════════════════════════════════════════════════════════

    /// Create the message bytes to sign for a block vote.
    ///
    /// Includes domain separation to prevent cross-shard replay attacks:
    /// - Domain tag ("BLOCK_VOTE")
    /// - Shard group identifier
    /// - Block height
    /// - Round number
    /// - Block hash
    ///
    /// This is a public method so the runner can use it for verification.
    /// Uses the centralized `block_vote_message` from `hyperscale_types::signing`.
    pub fn block_vote_message(
        shard_group: ShardGroupId,
        height: u64,
        round: u64,
        block_hash: &Hash,
    ) -> Vec<u8> {
        hyperscale_types::block_vote_message(shard_group, height, round, block_hash)
    }

    /// Get the shard group ID (needed for signing message construction).
    pub fn shard_group(&self) -> ShardGroupId {
        self.shard_group
    }

    /// Initialize with genesis block (for fresh start).
    pub fn initialize_genesis(&mut self, genesis: Block) -> Vec<Action> {
        let hash = genesis.hash();

        // CRITICAL: Set chain-committed state version from genesis block header.
        // The genesis block's state_version reflects the JMT state after genesis bootstrap
        // (e.g., Radix Engine initialization). Without this, proposers would compute
        // state_version starting from 0, while the JMT is actually at a higher version.
        self.last_chain_committed_state_version = genesis.header.state_version;

        self.genesis_block = Some(genesis.clone());
        self.committed_hash = hash;

        info!(
            validator = ?self.validator_id(),
            genesis_hash = ?hash,
            genesis_state_version = self.last_chain_committed_state_version,
            "Initialized genesis block"
        );

        // Set initial timers
        vec![
            Action::SetTimer {
                id: TimerId::Proposal,
                duration: self.config.proposal_interval,
            },
            Action::SetTimer {
                id: TimerId::Cleanup,
                duration: self.config.cleanup_interval,
            },
        ]
    }

    /// Request recovery from storage.
    ///
    /// Call this on startup to restore state from persistent storage.
    /// The runner will respond with `Event::ChainMetadataFetched`.
    pub fn request_recovery(&self) -> Vec<Action> {
        info!(
            validator = ?self.validator_id(),
            "Requesting chain metadata for recovery"
        );
        vec![Action::FetchChainMetadata]
    }

    /// Handle chain metadata fetched from storage (recovery).
    ///
    /// Called when the runner completes `Action::FetchChainMetadata`.
    #[instrument(skip(self, qc), fields(height = height.0, has_hash = hash.is_some(), has_qc = qc.is_some()))]
    pub fn on_chain_metadata_fetched(
        &mut self,
        height: BlockHeight,
        hash: Option<Hash>,
        qc: Option<QuorumCertificate>,
    ) -> Vec<Action> {
        if height.0 == 0 && hash.is_none() {
            // No committed blocks - this is a fresh start
            info!(
                validator = ?self.validator_id(),
                "No committed blocks found - fresh start"
            );
            return vec![];
        }

        // Restore committed state
        self.committed_height = height.0;
        if let Some(h) = hash {
            self.committed_hash = h;
        }
        self.latest_qc = qc.clone();

        // Reset backoff tracking - we're starting fresh at this height
        self.view_at_height_start = self.view;

        // Clean up any votes for heights at or below the committed height.
        // This handles the case where we loaded votes from storage that are now stale.
        let removed_blocks = self.cleanup_old_state(height.0);

        info!(
            validator = ?self.validator_id(),
            committed_height = self.committed_height,
            committed_hash = ?self.committed_hash,
            has_qc = qc.is_some(),
            "Recovered chain state from storage"
        );

        // Set timers to resume consensus and background tasks
        let mut actions = vec![
            Action::SetTimer {
                id: TimerId::Proposal,
                duration: self.config.proposal_interval,
            },
            Action::SetTimer {
                id: TimerId::Cleanup,
                duration: self.config.cleanup_interval,
            },
        ];

        // Cancel any pending fetches for removed blocks
        for block_hash in removed_blocks {
            actions.push(Action::CancelFetch { block_hash });
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Proposer Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle proposal timer - build and broadcast a new block.
    ///
    /// Takes ready transactions from mempool (already sectioned and hash-sorted),
    /// plus deferrals, aborts, and certificates from execution.
    #[instrument(skip(self, ready_txs, deferred, aborted, certificates, commitment_proofs), fields(
        tx_count = ready_txs.len(),
        deferred_count = deferred.len(),
        aborted_count = aborted.len(),
        cert_count = certificates.len(),
        proof_count = commitment_proofs.len()
    ))]
    pub fn on_proposal_timer(
        &mut self,
        ready_txs: &ReadyTransactions,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        certificates: Vec<Arc<TransactionCertificate>>,
        commitment_proofs: std::collections::HashMap<Hash, CommitmentProof>,
    ) -> Vec<Action> {
        // The next height to propose is one above the highest certified block,
        // NOT one above the committed block. This allows the chain to grow
        // while waiting for the two-chain commit rule to be satisfied.
        let next_height = self
            .latest_qc
            .as_ref()
            .map(|qc| qc.height.0 + 1)
            .unwrap_or(self.committed_height + 1);
        let round = self.view;

        debug!(
            validator = ?self.validator_id(),
            height = next_height,
            round = round,
            "Proposal timer fired"
        );

        // Reschedule the timer
        let actions = vec![Action::SetTimer {
            id: TimerId::Proposal,
            duration: self.config.proposal_interval,
        }];

        // Check if we should propose
        if !self.should_propose(next_height, round) {
            trace!(
                validator = ?self.validator_id(),
                expected = ?self.proposer_for(next_height, round),
                "Not the proposer for this height/round"
            );
            return actions;
        }

        // Check if we've already voted at this height.
        // If we have, don't propose again - we're committed to that block.
        // Re-proposing would create a different block hash (due to timestamp)
        // which we cannot vote for (vote locking).
        if self.voted_heights.contains_key(&next_height) {
            trace!(
                validator = ?self.validator_id(),
                height = next_height,
                round = round,
                "Already voted at this height, skipping proposal"
            );
            return actions;
        }

        // If we're syncing, propose an empty sync block instead of a full block.
        // This keeps the chain advancing while we catch up on execution state.
        if self.syncing {
            return self.build_and_broadcast_sync_block(next_height, round);
        }

        // Build and broadcast block - parent is the latest certified block
        let (parent_hash, parent_qc) = if let Some(qc) = &self.latest_qc {
            (qc.block_hash, qc.clone())
        } else {
            (self.committed_hash, QuorumCertificate::genesis())
        };

        // Use sectioned transactions directly from mempool (already hash-sorted per section)
        let retry_transactions: Vec<Arc<RoutableTransaction>> = ready_txs.retries.clone();
        let priority_transactions: Vec<Arc<RoutableTransaction>> = ready_txs.priority.clone();
        let other_transactions: Vec<Arc<RoutableTransaction>> = ready_txs.others.clone();

        let timestamp = self.now.as_millis() as u64;
        let block_height = BlockHeight(next_height);

        // Set block_height on each deferral (proposer fills this in).
        // Also filter out deferrals whose CycleProof doesn't have enough signers.
        // This prevents proposing blocks that other validators would reject due to
        // insufficient quorum on the cycle proof.
        let deferred_with_height: Vec<TransactionDefer> = deferred
            .into_iter()
            .filter(|d| {
                let source_shard = d.proof.winner_source_shard();
                let quorum_threshold = self.topology.quorum_threshold_for_shard(source_shard);
                let signer_count = d.proof.winner_commitment.signer_count() as u64;
                if signer_count < quorum_threshold {
                    trace!(
                        tx_hash = %d.tx_hash,
                        signer_count = signer_count,
                        quorum_threshold = quorum_threshold,
                        "Filtering deferral with insufficient CycleProof signers"
                    );
                    return false;
                }
                true
            })
            .map(|mut d| {
                d.block_height = block_height;
                d
            })
            .collect();

        // Set block_height on each abort
        let aborted_with_height: Vec<TransactionAbort> = aborted
            .into_iter()
            .map(|mut a| {
                a.block_height = block_height;
                a
            })
            .collect();

        // Walk the QC chain to find certificates already in pending blocks.
        // We exclude these from our proposal to avoid duplicates.
        let mut qc_chain_cert_hashes: std::collections::HashSet<Hash> =
            std::collections::HashSet::new();

        let mut current_hash = parent_hash;
        while let Some(block) = self.get_block_by_hash(current_hash) {
            let block_height = block.header.height.0;

            // Stop when we reach or go below committed height
            if block_height <= self.committed_height {
                break;
            }

            for cert in &block.certificates {
                qc_chain_cert_hashes.insert(cert.transaction_hash);
            }

            current_hash = block.header.parent_hash;
        }

        // Include certificates (limit by config), excluding those already in QC chain blocks
        let certificates_to_propose: Vec<_> = certificates
            .into_iter()
            .filter(|c| !qc_chain_cert_hashes.contains(&c.transaction_hash))
            .take(self.config.max_certificates_per_block)
            .collect();

        // Get parent's state from its block header.
        // This is the base state that verifiers will use.
        let (parent_state_root, parent_state_version) = self
            .get_block_by_hash(parent_hash)
            .map(|b| (b.header.state_root, b.header.state_version))
            .unwrap_or_else(|| {
                // Parent not found - use local JMT state as fallback.
                // This handles genesis case and edge cases where the parent block
                // is missing from pending_blocks (e.g., after recovery or sync).
                let (version, root) = self.get_local_jmt_state();
                (root, version)
            });

        // Build set of certificate hashes for stale deferral filtering
        let cert_hash_set: std::collections::HashSet<Hash> = certificates_to_propose
            .iter()
            .map(|c| c.transaction_hash)
            .collect();

        // Filter out stale deferrals (where the winner or loser tx is in this block's certs)
        let deferred_filtered: Vec<TransactionDefer> = deferred_with_height
            .into_iter()
            .filter(|d| {
                let hyperscale_types::DeferReason::LivelockCycle { winner_tx_hash } = &d.reason;
                !cert_hash_set.contains(winner_tx_hash) && !cert_hash_set.contains(&d.tx_hash)
            })
            .collect();

        // Track that we have a pending proposal (for correlation)
        self.pending_proposal = Some(PendingProposal {
            height: block_height,
            round,
        });

        info!(
            validator = ?self.validator_id(),
            height = next_height,
            round = round,
            transactions = retry_transactions.len() + priority_transactions.len() + other_transactions.len(),
            certificates = certificates_to_propose.len(),
            "Requesting block build for proposal"
        );

        // Always use BuildProposal - the runner handles JMT readiness and timeout.
        // This ensures transactions are always included regardless of certificate state.
        // Include SetTimer to reschedule the proposal timer.
        vec![
            Action::SetTimer {
                id: TimerId::Proposal,
                duration: self.config.proposal_interval,
            },
            Action::BuildProposal {
                proposer: self.validator_id(),
                height: block_height,
                round,
                parent_hash,
                parent_qc: parent_qc.clone(),
                timestamp,
                is_fallback: false,
                parent_state_root,
                parent_state_version,
                retry_transactions,
                priority_transactions,
                transactions: other_transactions,
                certificates: certificates_to_propose,
                commitment_proofs,
                deferred: deferred_filtered,
                aborted: aborted_with_height,
            },
        ]
    }

    /// Build and broadcast a fallback block during view change.
    ///
    /// Fallback blocks are created when the original proposer times out and a view
    /// change completes. The new proposer (determined by height + new_round rotation)
    /// creates an empty block to advance the chain.
    ///
    /// # Important Properties
    ///
    /// - **Empty payload**: No transactions, certificates, or aborts
    /// - **Timestamp inheritance**: Uses parent's weighted timestamp (prevents time manipulation)
    /// - **is_fallback: true**: Marks this as a fallback block
    ///
    /// # Returns
    ///
    /// Actions to broadcast the fallback block header and vote on it.
    fn build_and_broadcast_fallback_block(&mut self, height: u64, round: u64) -> Vec<Action> {
        let mut actions = vec![];

        // Get parent info from latest QC
        let (parent_hash, parent_qc) = if let Some(qc) = &self.latest_qc {
            (qc.block_hash, qc.clone())
        } else {
            (self.committed_hash, QuorumCertificate::genesis())
        };

        // Fallback blocks inherit the parent's timestamp - this prevents time manipulation
        // during view changes where a Byzantine proposer might try to advance consensus time
        let timestamp = parent_qc.weighted_timestamp_ms;

        // Fallback blocks have no certificates, so state doesn't change.
        // We inherit state_root and state_version from the parent block's header.
        let (parent_state_root, parent_state_version) = self
            .get_block_by_hash(parent_hash)
            .map(|b| (b.header.state_root, b.header.state_version))
            .unwrap_or_else(|| {
                // Genesis case - use local JMT state
                let (version, root) = self.get_local_jmt_state();
                (root, version)
            });
        let state_version = parent_state_version;
        let state_root = parent_state_root;

        let header = BlockHeader {
            height: BlockHeight(height),
            parent_hash,
            parent_qc: parent_qc.clone(),
            proposer: self.validator_id(),
            timestamp,
            round,
            is_fallback: true,
            state_root,
            state_version,
            transaction_root: Hash::ZERO, // Fallback blocks have no transactions
        };

        let block = Block {
            header: header.clone(),
            retry_transactions: vec![], // Empty - fallback blocks have no transactions
            priority_transactions: vec![], // Empty
            transactions: vec![],       // Empty
            certificates: vec![],       // Empty
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(), // Empty - no transactions
        };

        let block_hash = block.hash();

        info!(
            validator = ?self.validator_id(),
            height = height,
            round = round,
            block_hash = ?block_hash,
            "Building fallback block (leader timeout)"
        );

        // Store our own block as pending (already complete since it's empty)
        let mut pending = PendingBlock::new(header.clone(), vec![], vec![], vec![], vec![]);
        if let Ok(constructed) = pending.construct_block() {
            self.pending_blocks.insert(block_hash, pending);
            self.pending_block_created_at.insert(block_hash, self.now);
            self.certified_blocks
                .insert(block_hash, ((*constructed).clone(), parent_qc));
        }

        // Create gossip message (fallback blocks have no transactions, deferrals, or aborts)
        let gossip = hyperscale_messages::BlockHeaderGossip::new(header, vec![], vec![], vec![]);

        // Track proposal time for rate limiting
        self.last_proposal_time = self.now;

        // Record leader activity - we are producing blocks
        self.record_leader_activity();

        actions.push(Action::BroadcastBlockHeader {
            shard: self.local_shard(),
            header: Box::new(gossip),
        });

        // Vote for our own fallback block
        actions.extend(self.create_vote(block_hash, height, round));

        // Set proposal timer in case this fallback block doesn't get quorum.
        // Without this timer, consensus could stall if the block doesn't reach quorum.
        actions.push(Action::SetTimer {
            id: TimerId::Proposal,
            duration: self.config.proposal_interval,
        });

        actions
    }

    /// Build and broadcast an empty block while syncing.
    ///
    /// Sync blocks allow the chain to keep advancing even when the proposer
    /// can't execute transactions (because they're catching up). Other validators
    /// will include transactions when it's their turn to propose.
    ///
    /// # Key Differences from Fallback Blocks
    ///
    /// | Aspect | Sync Block | Fallback Block |
    /// |--------|------------|----------------|
    /// | Trigger | Proposer is syncing | Leader timeout |
    /// | Timestamp | Normal (`self.now`) | Inherited from parent |
    /// | `is_fallback` | `false` | `true` |
    /// | Cadence | Normal proposal interval | After 3s timeout |
    ///
    /// Sync blocks use normal timestamps because the proposer is online with
    /// an accurate clock - they just can't execute transactions.
    fn build_and_broadcast_sync_block(&mut self, height: u64, round: u64) -> Vec<Action> {
        let mut actions = vec![];

        // Get parent info from latest QC
        let (parent_hash, parent_qc) = if let Some(qc) = &self.latest_qc {
            (qc.block_hash, qc.clone())
        } else {
            (self.committed_hash, QuorumCertificate::genesis())
        };

        // Sync blocks use normal timestamps - the proposer is online with a good clock,
        // they just can't execute transactions. This differs from fallback blocks which
        // inherit the parent timestamp (proposed after timeout, clock may have drifted).
        let timestamp = self.now.as_millis() as u64;

        // Sync blocks have no certificates, so state doesn't change.
        // We inherit state_root and state_version from the parent block's header.
        let (parent_state_root, parent_state_version) = self
            .get_block_by_hash(parent_hash)
            .map(|b| (b.header.state_root, b.header.state_version))
            .unwrap_or_else(|| {
                // Genesis case - use local JMT state
                let (version, root) = self.get_local_jmt_state();
                (root, version)
            });
        let state_version = parent_state_version;
        let state_root = parent_state_root;

        let header = BlockHeader {
            height: BlockHeight(height),
            parent_hash,
            parent_qc: parent_qc.clone(),
            proposer: self.validator_id(),
            timestamp,
            round,
            is_fallback: false, // Not a fallback - just empty due to sync
            state_root,
            state_version,
            transaction_root: Hash::ZERO, // Sync blocks have no transactions
        };

        let block = Block {
            header: header.clone(),
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        };

        let block_hash = block.hash();

        info!(
            validator = ?self.validator_id(),
            height = height,
            round = round,
            block_hash = ?block_hash,
            "Building sync block (syncing, empty payload)"
        );

        // Store our own block as pending (already complete since it's empty)
        let mut pending = PendingBlock::new(header.clone(), vec![], vec![], vec![], vec![]);
        if let Ok(constructed) = pending.construct_block() {
            self.pending_blocks.insert(block_hash, pending);
            self.pending_block_created_at.insert(block_hash, self.now);
            self.certified_blocks
                .insert(block_hash, ((*constructed).clone(), parent_qc));
        }

        // Create gossip message (sync blocks have no transactions, deferrals, or aborts)
        let gossip = hyperscale_messages::BlockHeaderGossip::new(header, vec![], vec![], vec![]);

        // Track proposal time for rate limiting
        self.last_proposal_time = self.now;

        // Record leader activity - we are producing blocks
        self.record_leader_activity();

        actions.push(Action::BroadcastBlockHeader {
            shard: self.local_shard(),
            header: Box::new(gossip),
        });

        // Vote for our own sync block
        actions.extend(self.create_vote(block_hash, height, round));

        // Set proposal timer for next round
        actions.push(Action::SetTimer {
            id: TimerId::Proposal,
            duration: self.config.proposal_interval,
        });

        actions
    }

    /// Re-propose a block we're vote-locked to after a view change.
    ///
    /// When we've already voted for a block at this height but become leader after
    /// a view change, we must re-propose the same block (with updated round) rather
    /// than creating a new fallback block. This allows other validators who may have
    /// missed the original proposal to receive and vote on it.
    ///
    /// # Safety
    ///
    /// This is safe because:
    /// - We already validated and voted for this block
    /// - The block hash remains the same (only round changes in header)
    /// - Other validators can now receive and vote for it
    /// - If enough validators vote, the block commits
    ///
    /// # Returns
    ///
    /// Actions to re-broadcast the block header. We do NOT create a new vote since
    /// we already voted for this block at this height.
    fn repropose_locked_block(&mut self, block_hash: Hash, height: u64) -> Vec<Action> {
        let mut actions = vec![];

        // Try to get the pending block we voted for
        let Some(pending) = self.pending_blocks.get(&block_hash) else {
            // Block not in pending_blocks - might have been cleaned up or committed
            // Fall back to just setting the proposal timer
            warn!(
                validator = ?self.validator_id(),
                height = height,
                block_hash = ?block_hash,
                "Cannot re-propose: locked block not found in pending_blocks"
            );
            return vec![Action::SetTimer {
                id: TimerId::Proposal,
                duration: self.config.proposal_interval,
            }];
        };

        // IMPORTANT: Keep the original header unchanged, including the round.
        //
        // The block hash is computed from all header fields INCLUDING round.
        // If we change the round, we change the hash, which would break vote-locking
        // (validators voted for the original hash, not a new one).
        //
        // Receivers will accept this block with an older round because:
        // 1. The proposer is valid for (height, original_round)
        // 2. Their view >= original_round (they've also been through view change)
        // 3. validate_header allows blocks where proposer matches (height, header.round)
        let header = pending.header().clone();
        let original_round = header.round;

        // Get all the hashes and metadata needed to reconstruct the gossip message
        let retry_hashes = pending.retry_hashes().to_vec();
        let priority_hashes = pending.priority_hashes().to_vec();
        let tx_hashes = pending.other_hashes().to_vec();
        let cert_hashes = pending.all_certificate_hashes();
        let deferred = pending.deferred().to_vec();
        let aborted = pending.aborted().to_vec();
        let commitment_proofs = pending.commitment_proofs().clone();

        let total_tx_count = retry_hashes.len() + priority_hashes.len() + tx_hashes.len();
        info!(
            validator = ?self.validator_id(),
            height = height,
            original_round = original_round,
            block_hash = ?block_hash,
            tx_count = total_tx_count,
            cert_count = cert_hashes.len(),
            "Re-proposing vote-locked block after view change (keeping original round)"
        );

        // Create and broadcast the gossip message - include commitment proofs for ordering validation
        let gossip = hyperscale_messages::BlockHeaderGossip::full(
            header,
            retry_hashes,
            priority_hashes,
            tx_hashes,
            cert_hashes,
            deferred,
            aborted,
            commitment_proofs,
        );

        actions.push(Action::BroadcastBlockHeader {
            shard: self.local_shard(),
            header: Box::new(gossip),
        });

        // Note: We do NOT create a new vote here - we already voted for this block
        // at this height. The vote is recorded in voted_heights and our original
        // vote should still be valid (votes are for block_hash + height, not round).

        // Track proposal time for rate limiting
        self.last_proposal_time = self.now;

        // Record leader activity - we are producing blocks
        self.record_leader_activity();

        // Set proposal timer in case this re-proposal also fails to gather quorum
        actions.push(Action::SetTimer {
            id: TimerId::Proposal,
            duration: self.config.proposal_interval,
        });

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Header Reception
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle received block header.
    ///
    /// Note: The sender identity is not passed as a parameter anymore.
    /// Sender identity comes from the header's proposer field (ValidatorId),
    /// which is signed and verified. For sync detection, we don't need
    /// the network peer ID.
    #[instrument(skip(self, header, retry_hashes, priority_hashes, tx_hashes, cert_hashes, deferred, aborted, mempool, certificates), fields(
        height = header.height.0,
        round = header.round,
        proposer = ?header.proposer,
        tx_count = retry_hashes.len() + priority_hashes.len() + tx_hashes.len()
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_header(
        &mut self,
        header: BlockHeader,
        retry_hashes: Vec<Hash>,
        priority_hashes: Vec<Hash>,
        tx_hashes: Vec<Hash>,
        cert_hashes: Vec<Hash>,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        commitment_proofs: HashMap<Hash, CommitmentProof>,
        mempool: &HashMap<Hash, Arc<RoutableTransaction>>,
        certificates: &HashMap<Hash, Arc<TransactionCertificate>>,
    ) -> Vec<Action> {
        let block_hash = header.hash();
        let height = header.height.0;
        let round = header.round;

        debug!(
            validator = ?self.validator_id(),
            proposer = ?header.proposer,
            height = height,
            round = round,
            block_hash = ?block_hash,
            "Received block header"
        );

        // Track whether we need to sync (will be added to actions at the end)
        let mut sync_actions = Vec::new();

        // Check if this header reveals we're missing blocks and need to sync.
        // The parent_qc certifies block at height N-1 for a block at height N.
        //
        // We check if we actually have the parent block (at parent_height) in any state:
        // - committed (already persisted)
        // - pending_blocks (received via consensus, may be waiting for transactions)
        // - certified_blocks (has QC, waiting for 2-chain commit)
        // - pending_synced_block_verifications (received via sync, verifying QC)
        //
        // If missing, we trigger sync but CONTINUE processing the header. This allows
        // syncing validators to still participate in consensus at the tip (building QCs,
        // proposing empty sync blocks) while catching up on historical blocks in parallel.
        if !header.parent_qc.is_genesis() {
            let parent_height = header.parent_qc.height.0;
            let parent_block_hash = header.parent_qc.block_hash;

            // Check if we have a COMPLETE parent block. If the parent is incomplete
            // (missing transactions/certificates), we need to sync to get the full data.
            // This is more aggressive than checking has_block_at_height() which would
            // return true for incomplete pending blocks.
            let have_parent = self.has_complete_block_at_height(parent_height);

            if !have_parent {
                let target_height = parent_height;
                let target_hash = parent_block_hash;

                info!(
                    validator = ?self.validator_id(),
                    committed_height = self.committed_height,
                    parent_height = parent_height,
                    target_height = target_height,
                    "Missing parent block, triggering sync (continuing to process header)"
                );

                // Queue sync action but DON'T return - continue processing the header.
                // This allows us to build QCs and propose sync blocks while syncing.
                // start_sync sets the syncing flag immediately and returns StartSync action.
                sync_actions = self.start_sync(target_height, target_hash);
            }

            // Only update latest_qc if we actually have the parent block it references.
            // If we don't have the parent, we can't use this QC for proposing because
            // we won't be able to look up the parent's state_root. This prevents
            // proposing blocks with state_root=Hash::ZERO when the parent is missing.
            let should_update_qc = have_parent
                && self
                    .latest_qc
                    .as_ref()
                    .is_none_or(|existing| header.parent_qc.height.0 > existing.height.0);
            if should_update_qc {
                debug!(
                    validator = ?self.validator_id(),
                    qc_height = header.parent_qc.height.0,
                    "Updated latest_qc from received block header"
                );
                self.latest_qc = Some(header.parent_qc.clone());
                self.maybe_unlock_for_qc(&header.parent_qc);
            }
        }

        // View synchronization from block header round.
        // When we receive a block proposed at round R > our view, we know the network
        // has made progress and we should catch up. This helps late joiners converge
        // faster than waiting for QC-based sync alone.
        if round > self.view {
            info!(
                validator = ?self.validator_id(),
                old_view = self.view,
                new_view = round,
                header_height = height,
                "View synchronization: advancing view to match received block header"
            );
            self.view = round;
        }

        // Basic validation
        if let Err(e) = self.validate_header(&header) {
            warn!(
                validator = ?self.validator_id(),
                error = %e,
                "Invalid block header"
            );
            return vec![];
        }

        // Record leader activity for receiving a valid header.
        // Rate-limited to once per (height, round) to prevent Byzantine leaders
        // from spamming different headers to delay view changes.
        self.record_header_activity(height, round);

        // Check if we already have this block
        if self.pending_blocks.contains_key(&block_hash) {
            trace!("Already have pending block {}", block_hash);
            return vec![];
        }

        // Create pending block with deferrals, aborts, and commitment proofs
        let mut pending = PendingBlock::with_proofs(
            header.clone(),
            retry_hashes.clone(),
            priority_hashes.clone(),
            tx_hashes.clone(),
            cert_hashes.clone(),
            deferred,
            aborted,
            commitment_proofs,
        );

        // Try to fill in transactions from mempool (all sections)
        for tx_hash in retry_hashes
            .iter()
            .chain(priority_hashes.iter())
            .chain(tx_hashes.iter())
        {
            if let Some(tx) = mempool.get(tx_hash) {
                pending.add_transaction_arc(Arc::clone(tx));
            }
        }

        // Try to fill in certificates from local certificate store
        for cert_hash in &cert_hashes {
            if let Some(cert) = certificates.get(cert_hash) {
                pending.add_certificate(Arc::clone(cert));
            }
        }

        // Store pending block with creation timestamp for stale detection
        self.pending_blocks.insert(block_hash, pending);
        self.pending_block_created_at.insert(block_hash, self.now);

        // Check if we have buffered votes for this block that can now trigger verification
        // (Votes may arrive before the header due to network timing)
        if let Some(vote_set) = self.vote_sets.get_mut(&block_hash) {
            // Update the vote set with header info (needed for parent_block_hash in QC)
            vote_set.set_header(&header);
            info!(
                block_hash = ?block_hash,
                "Updated VoteSet with header info via on_block_header"
            );
        }

        // Check if we should trigger verification now that we have the header
        let mut actions = self.maybe_trigger_vote_verification(block_hash);

        // Always include sync actions if we need to sync
        actions.extend(sync_actions);

        // If vote verification was triggered, return those actions.
        // But don't return early just for sync - we still want to vote on the block.
        if actions
            .iter()
            .any(|a| matches!(a, Action::VerifyQcSignature { .. }))
        {
            return actions;
        }

        // If block is complete, construct it and proceed to voting (after QC verification)
        let is_complete = self
            .pending_blocks
            .get(&block_hash)
            .is_some_and(|p| p.is_complete());

        if is_complete {
            // Construct the block so it's available for commit later
            if let Some(pending) = self.pending_blocks.get_mut(&block_hash) {
                if pending.block().is_none() {
                    if let Err(e) = pending.construct_block() {
                        warn!("Failed to construct block {}: {}", block_hash, e);
                        return actions;
                    }
                }
            }

            // Trigger QC verification (for non-genesis) or vote directly (for genesis)
            actions.extend(self.trigger_qc_verification_or_vote(block_hash));
            return actions;
        }

        // Block not complete yet - don't fetch immediately!
        // Wait for the configured timeout to give gossip/local creation a chance.
        // The cleanup timer calls check_pending_block_fetches() periodically to
        // emit fetch requests for blocks that have been waiting long enough.
        //
        // This reduces unnecessary network traffic:
        // - Transactions often arrive via gossip before we need to fetch
        // - Certificates can be created locally from state certificates
        if let Some(pending) = self.pending_blocks.get(&block_hash) {
            debug!(
                validator = ?self.validator_id(),
                block_hash = ?block_hash,
                missing_txs = pending.missing_transaction_count(),
                missing_certs = pending.missing_certificate_count(),
                tx_timeout_ms = self.config.transaction_fetch_timeout.as_millis(),
                cert_timeout_ms = self.config.certificate_fetch_timeout.as_millis(),
                "Block incomplete, will fetch after timeout if still missing"
            );
        }

        actions
    }

    /// Collect public keys for QC signers (helper for delegated verification).
    ///
    /// Returns the public keys for all signers in committee order, or None if any key is missing.
    fn collect_qc_signer_keys(&self, _qc: &QuorumCertificate) -> Option<Vec<Bls12381G1PublicKey>> {
        let committee_size = self.topology.local_committee_size();
        let mut pubkeys = Vec::with_capacity(committee_size);

        // We need to pass ALL committee keys in order, and the runner will filter
        // by the bitfield. This ensures consistent ordering.
        for idx in 0..committee_size {
            if let Some(validator_id) = self.topology.local_validator_at_index(idx) {
                if let Some(pk) = self.public_key(validator_id) {
                    pubkeys.push(pk);
                } else {
                    warn!(validator_id = ?validator_id, "Missing public key for committee member");
                    return None;
                }
            } else {
                warn!(idx = idx, "Invalid committee index");
                return None;
            }
        }

        Some(pubkeys)
    }

    /// Validate a block header.
    ///
    /// Key insight: we validate the header's *internal consistency* and its parent_qc,
    /// but we don't require the header to match our current state. The header might
    /// be ahead of us (we'll catch up via the parent_qc it carries).
    fn validate_header(&self, header: &BlockHeader) -> Result<(), String> {
        let height = header.height.0;
        let round = header.round;

        // Check height is above what we've committed (reject old blocks)
        if height <= self.committed_height {
            return Err(format!(
                "height {} is at or below committed height {}",
                height, self.committed_height
            ));
        }

        // Check proposer is correct for this height/round
        let expected_proposer = self.proposer_for(height, round);
        if header.proposer != expected_proposer {
            return Err(format!(
                "wrong proposer: expected {:?}, got {:?}",
                expected_proposer, header.proposer
            ));
        }

        // Verify parent QC has quorum (if not genesis)
        if !header.parent_qc.is_genesis() {
            let has_quorum =
                VotePower::has_quorum(header.parent_qc.voting_power.0, self.total_voting_power());
            if !has_quorum {
                return Err("parent QC does not have quorum".to_string());
            }

            // The parent QC's height should be one less than this block's height
            if header.parent_qc.height.0 + 1 != height {
                return Err(format!(
                    "parent QC height {} doesn't match block height {} - 1",
                    header.parent_qc.height.0, height
                ));
            }

            // The parent hash should match the QC's block hash
            if header.parent_hash != header.parent_qc.block_hash {
                return Err(format!(
                    "parent_hash {:?} doesn't match parent_qc.block_hash {:?}",
                    header.parent_hash, header.parent_qc.block_hash
                ));
            }

            // NOTE: QC signature verification is done asynchronously via Action::VerifyQcSignature.
            // The caller (on_block_header) will delegate verification before voting.
        } else {
            // Genesis QC - this should only be for height 1
            if height != self.committed_height + 1 {
                return Err(format!(
                    "genesis QC only valid for first block after committed height, got height {}",
                    height
                ));
            }
        }

        // Validate timestamp is within acceptable bounds
        self.validate_timestamp(header)?;

        Ok(())
    }

    /// Validate that the proposer's timestamp is within acceptable bounds.
    ///
    /// The timestamp must not be:
    /// - More than `max_timestamp_delay_ms` behind our clock (stale block)
    /// - More than `max_timestamp_rush_ms` ahead of our clock (time manipulation)
    ///
    /// This validation prevents proposers from manipulating consensus time while
    /// allowing for reasonable clock drift between validators.
    ///
    /// # Special Cases
    ///
    /// - **Genesis blocks**: Skip validation (timestamp is fixed at 0)
    /// - **Fallback blocks**: Skip validation (they inherit parent's weighted timestamp,
    ///   which may be older than the delay threshold during extended view changes)
    fn validate_timestamp(&self, header: &BlockHeader) -> Result<(), String> {
        // Skip timestamp validation for genesis blocks (timestamp is fixed at 0)
        if header.is_genesis() {
            return Ok(());
        }

        // Skip timestamp validation for fallback blocks.
        //
        // Fallback blocks inherit their parent's weighted_timestamp_ms to prevent
        // time manipulation during view changes. This timestamp may be older than
        // max_timestamp_delay_ms if multiple view changes occur in succession.
        //
        // This is safe because:
        // 1. Fallback blocks are empty (no transactions) so they can't manipulate state
        // 2. The timestamp comes from a QC, which was already validated
        // 3. The weighted timestamp will be corrected when normal blocks resume
        if header.is_fallback {
            return Ok(());
        }

        let now = self.now.as_millis() as u64;

        // Check if timestamp is too old
        if header.timestamp < now.saturating_sub(self.config.max_timestamp_delay_ms) {
            return Err(format!(
                "proposer timestamp {} is too old (now: {}, max delay: {}ms)",
                header.timestamp, now, self.config.max_timestamp_delay_ms
            ));
        }

        // Check if timestamp is too far in the future
        if header.timestamp > now + self.config.max_timestamp_rush_ms {
            return Err(format!(
                "proposer timestamp {} is too far ahead (now: {}, max rush: {}ms)",
                header.timestamp, now, self.config.max_timestamp_rush_ms
            ));
        }

        Ok(())
    }

    /// Trigger QC verification (if needed) and then vote on a complete block.
    ///
    /// This is the single entry point for voting on a block after it becomes complete.
    /// It handles:
    /// 1. Non-genesis QC: Triggers async signature verification, vote happens in callback
    /// 2. Genesis QC: Votes directly (no signature to verify)
    ///
    /// SAFETY: This must be called instead of `try_vote_on_block` directly to ensure
    /// QC signatures are always verified before voting.
    fn trigger_qc_verification_or_vote(&mut self, block_hash: Hash) -> Vec<Action> {
        let Some(pending) = self.pending_blocks.get(&block_hash) else {
            warn!(
                "trigger_qc_verification_or_vote: no pending block for {}",
                block_hash
            );
            return vec![];
        };

        let header = pending.header().clone();
        let height = header.height.0;
        let round = header.round;

        // For non-genesis QC, delegate signature verification before voting.
        // This is CRITICAL for BFT safety - prevents Byzantine proposers from
        // including fake QCs with invalid signatures.
        if !header.parent_qc.is_genesis() {
            // Check if we've already verified this exact QC (by its block_hash).
            // This happens during view changes when multiple proposals at the same
            // height share the same parent_qc. Avoids redundant crypto work.
            let qc_block_hash = header.parent_qc.block_hash;
            if self.verified_qcs.contains_key(&qc_block_hash) {
                trace!(
                    qc_block_hash = ?qc_block_hash,
                    block_hash = ?block_hash,
                    "QC already verified, skipping re-verification"
                );
                return self.try_vote_on_block(block_hash, height, round);
            }

            // Check if we already have pending verification for this block
            if self.pending_qc_verifications.contains_key(&block_hash) {
                trace!("QC verification already pending for block {}", block_hash);
                return vec![];
            }

            // Collect public keys for verification
            let Some(public_keys) = self.collect_qc_signer_keys(&header.parent_qc) else {
                warn!("Failed to collect public keys for QC verification");
                return vec![];
            };

            // Store pending verification info
            self.pending_qc_verifications.insert(
                block_hash,
                PendingQcVerification {
                    header: header.clone(),
                },
            );

            // Construct signing message with domain separation
            let signing_message = Self::block_vote_message(
                self.shard_group,
                header.parent_qc.height.0,
                header.parent_qc.round,
                &header.parent_qc.block_hash,
            );

            // Delegate verification to runner
            return vec![Action::VerifyQcSignature {
                qc: header.parent_qc.clone(),
                public_keys,
                block_hash,
                signing_message,
            }];
        }

        // Genesis QC - vote directly (no signature to verify)
        self.try_vote_on_block(block_hash, height, round)
    }

    /// Try to vote on a block after it's complete and QC is verified.
    ///
    /// NOTE: This should only be called after QC verification completes.
    /// For the main entry point, use `trigger_qc_verification_or_vote`.
    fn try_vote_on_block(&mut self, block_hash: Hash, height: u64, round: u64) -> Vec<Action> {
        // Check vote locking - have we already voted for a block at this height?
        // BFT Safety: A validator must not vote for conflicting blocks at the same height
        // in the same round. Across rounds, the vote lock may be released on timeout if
        // no QC has formed (see `advance_round`), or via QC-based unlock (see `maybe_unlock_for_qc`).
        if let Some(&(existing_hash, existing_round)) = self.voted_heights.get(&height) {
            if existing_hash == block_hash {
                // Already voted for this exact block (possibly in an earlier round)
                trace!(
                    validator = ?self.validator_id(),
                    block_hash = ?block_hash,
                    height = height,
                    round = round,
                    existing_round = existing_round,
                    "Already voted for this block"
                );
                return vec![];
            } else {
                // Vote locking prevented voting for a different block at this height.
                // This is expected during view changes: we voted in round N, then round N+1
                // proposes a different block, but we're locked to our original vote.
                // This is BFT safety working correctly, not a violation.
                debug!(
                    validator = ?self.validator_id(),
                    existing = ?existing_hash,
                    existing_round = existing_round,
                    new = ?block_hash,
                    new_round = round,
                    height = height,
                    "Vote locking: already voted for different block at this height"
                );
                return vec![];
            }
        }

        // Validate block contents before voting
        if let Some(pending) = self.pending_blocks.get(&block_hash) {
            if let Some(block) = pending.block() {
                // Validate deferrals and aborts
                if let Err(e) = self.validate_deferrals_and_aborts(&block) {
                    warn!(
                        validator = ?self.validator_id(),
                        block_hash = ?block_hash,
                        error = %e,
                        "Block has invalid deferrals/aborts - not voting"
                    );
                    return vec![];
                }

                // Validate transaction ordering
                if let Err(e) = self.validate_transaction_ordering(&block) {
                    warn!(
                        validator = ?self.validator_id(),
                        block_hash = ?block_hash,
                        error = %e,
                        "Block has invalid transaction ordering - not voting"
                    );
                    return vec![];
                }

                // Initiate all async verifications in parallel.
                // CycleProof, StateRoot, and TransactionRoot verifications run concurrently.
                let mut verification_actions = Vec::new();

                // If block has deferrals with CycleProofs, initiate async verification.
                if self.block_needs_cycle_proof_verification(&block) {
                    verification_actions
                        .extend(self.initiate_cycle_proof_verification(block_hash, &block));
                }

                // Verify state root if block has committed certificates.
                if self.block_needs_state_root_verification(&block) {
                    verification_actions
                        .extend(self.initiate_state_root_verification(block_hash, &block));
                }

                // Verify transaction root if block has transactions.
                if self.block_needs_transaction_root_verification(&block) {
                    verification_actions
                        .extend(self.initiate_transaction_root_verification(block_hash, &block));
                }

                // If any verifications were initiated, wait for them to complete.
                if !verification_actions.is_empty() {
                    return verification_actions;
                }
            }
        }

        // Create and send vote
        self.create_vote(block_hash, height, round)
    }

    /// Check if a block needs CycleProof verification before voting.
    ///
    /// Returns true if the block has any deferrals with CycleProofs that haven't
    /// been verified yet.
    fn block_needs_cycle_proof_verification(&self, block: &Block) -> bool {
        if block.deferred.is_empty() {
            return false;
        }

        let block_hash = block.hash();

        // Skip if already verified or verification in progress
        if self.verified_cycle_proofs.contains(&block_hash)
            || self
                .pending_cycle_proof_verifications
                .contains_key(&block_hash)
        {
            return false;
        }

        true
    }

    /// Initiate async CycleProof verification for a block's deferrals.
    ///
    /// This is called after structural validation passes. For each deferral,
    /// we emit an `Action::VerifyCycleProof` to verify the BLS signature.
    /// Voting is deferred until all verifications complete successfully.
    fn initiate_cycle_proof_verification(
        &mut self,
        block_hash: Hash,
        block: &Block,
    ) -> Vec<Action> {
        if block.deferred.is_empty() {
            return vec![];
        }

        debug!(
            block_hash = ?block_hash,
            deferral_count = block.deferred.len(),
            "Initiating CycleProof verification for block"
        );

        // Track pending verification
        self.pending_cycle_proof_verifications.insert(
            block_hash,
            PendingCycleProofVerifications {
                total: block.deferred.len(),
                verified: 0,
                all_valid: true,
            },
        );

        // Generate verification actions for each deferral's proof
        block
            .deferred
            .iter()
            .enumerate()
            .map(|(idx, deferral)| {
                let proof = &deferral.proof;
                let source_shard = proof.winner_source_shard();

                // Resolve public keys from signer bitfield
                let public_keys =
                    self.resolve_commitment_proof_signers(&proof.winner_commitment, source_shard);

                if public_keys.is_empty() {
                    warn!(
                        block_hash = ?block_hash,
                        deferral_index = idx,
                        "No public keys resolved for CycleProof verification"
                    );
                    // Will fail verification with empty keys
                }

                // Get signing message and quorum threshold
                // IMPORTANT: The CommitmentProof aggregates signatures from StateProvisions.
                // StateProvisions are signed with state_provision_message() which includes
                // target_shard (the shard receiving the provisions = our local shard).
                // We must use the same message format for verification.
                let entry_hashes: Vec<Hash> = proof
                    .winner_commitment
                    .entries
                    .iter()
                    .map(|e| e.hash())
                    .collect();
                let signing_message = state_provision_message(
                    &proof.winner_commitment.tx_hash,
                    self.shard_group, // target_shard = our local shard (we received these provisions)
                    source_shard,     // source_shard = where the provisions came from
                    proof.winner_commitment.block_height,
                    proof.winner_commitment.block_timestamp,
                    &entry_hashes,
                );
                let quorum_threshold = self.topology.quorum_threshold_for_shard(source_shard);

                Action::VerifyCycleProof {
                    block_hash,
                    deferral_index: idx,
                    cycle_proof: proof.clone(),
                    public_keys,
                    signing_message,
                    quorum_threshold,
                }
            })
            .collect()
    }

    /// Resolve public keys from a CommitmentProof's signer bitfield.
    fn resolve_commitment_proof_signers(
        &self,
        proof: &CommitmentProof,
        source_shard: ShardGroupId,
    ) -> Vec<Bls12381G1PublicKey> {
        let committee = self.topology.committee_for_shard(source_shard);
        proof
            .signers
            .set_indices()
            .filter_map(|idx| {
                committee
                    .get(idx)
                    .and_then(|vid| self.topology.public_key(*vid))
            })
            .collect()
    }

    /// Check if all async verifications are complete for a block.
    ///
    /// Returns true if:
    /// - CycleProof verification is done (or not needed)
    /// - State root verification is done (or not needed)
    /// - Transaction root verification is done (or not needed)
    ///
    /// Used by verification callbacks to determine if it's safe to vote.
    fn block_verifications_complete(&self, block: &Block) -> bool {
        let block_hash = block.hash();

        // Check CycleProof verification status
        let cycle_proof_ok = if block.deferred.is_empty() {
            // No deferrals - no verification needed
            true
        } else {
            // Has deferrals - must be in verified set
            self.verified_cycle_proofs.contains(&block_hash)
        };

        // Check state root verification status
        let state_root_ok = if block.certificates.is_empty() {
            // No certificates - no verification needed
            true
        } else {
            // Has certificates - must be in verified set
            self.verified_state_roots.contains(&block_hash)
        };

        // Check transaction root verification status
        let transaction_root_ok = if block.transaction_count() == 0 {
            // No transactions - no verification needed
            true
        } else {
            // Has transactions - must be in verified set
            self.verified_transaction_roots.contains(&block_hash)
        };

        cycle_proof_ok && state_root_ok && transaction_root_ok
    }

    /// Check if a block needs state root verification before voting.
    ///
    /// Returns true if the block has certificates (which change state)
    /// and we haven't already verified or initiated verification.
    fn block_needs_state_root_verification(&self, block: &Block) -> bool {
        if block.certificates.is_empty() {
            return false;
        }

        let block_hash = block.hash();

        // Skip if already verified, in-flight, or queued
        if self.verified_state_roots.contains(&block_hash)
            || self
                .state_root_verifications_in_flight
                .contains(&block_hash)
            || self
                .pending_state_root_verifications
                .contains_key(&block_hash)
        {
            return false;
        }

        true
    }

    /// Initiate state root verification for a block.
    ///
    /// Collects state writes from the block's certificates for our local shard.
    /// Uses the block header's state_version to derive the required base version, then
    /// either verifies immediately (if JMT is ready) or queues for later.
    ///
    /// The verification computes: base_jmt_state + block.certificate_writes and compares
    /// against block.header.state_root.
    ///
    /// The base version is derived from the block header, NOT our local committed state:
    /// base_version = header.state_version - len(certificates)
    ///
    /// This ensures deterministic verification across validators, since all validators
    /// see the same block header.
    ///
    /// If our JMT hasn't reached base_version yet, we queue the verification until
    /// `StateCommitComplete` brings us there.
    fn initiate_state_root_verification(&mut self, block_hash: Hash, block: &Block) -> Vec<Action> {
        // Get the parent block's state_root. This is the base state that the proposer
        // used when computing the new state_root. We must verify from the same base.
        let (_, current_root) = self.get_local_jmt_state();
        let parent_state_root = self
            .get_block_by_hash(block.header.parent_hash)
            .map(|parent| parent.header.state_root)
            .unwrap_or(current_root); // Genesis or missing parent - use current JMT root

        // Check if our local JMT root matches the parent's state_root.
        // This ensures we're computing from the same base state as the proposer.

        if current_root == parent_state_root {
            // JMT is ready - verify immediately
            debug!(
                block_hash = ?block_hash,
                certificate_count = block.certificates.len(),
                expected_root = ?block.header.state_root,
                parent_state_root = ?parent_state_root,
                current_jmt_root = ?current_root,
                "JMT ready - initiating state root verification"
            );

            self.state_root_verifications_in_flight.insert(block_hash);

            vec![Action::VerifyStateRoot {
                block_hash,
                parent_state_root,
                expected_root: block.header.state_root,
                certificates: block.certificates.clone(),
            }]
        } else {
            // JMT not ready - queue for later
            debug!(
                block_hash = ?block_hash,
                certificate_count = block.certificates.len(),
                expected_root = ?block.header.state_root,
                parent_state_root = ?parent_state_root,
                current_jmt_root = ?current_root,
                "JMT not ready - queueing state root verification"
            );

            self.pending_state_root_verifications.insert(
                block_hash,
                PendingStateRootVerification {
                    required_root: parent_state_root,
                    expected_root: block.header.state_root,
                    certificates: block.certificates.clone(),
                },
            );

            vec![] // No action yet - will be triggered by StateCommitComplete
        }
    }

    /// Validate deferrals and aborts in a proposed block (structural validation).
    ///
    /// # Validation Rules
    ///
    /// ## Deferrals (TransactionDefer)
    /// Always enforced (structural rules):
    /// - Hash ordering: deferred_hash > winner_hash (lower hash wins cycles)
    /// - Staleness: winner cert not in same block
    /// - Staleness: loser cert not in same block (loser already completed)
    /// - CycleProof required: every deferral must have a CycleProof attached
    /// - CycleProof consistency: proof's winner hash must match deferral reason
    ///
    /// Note: The CycleProof's BLS signature is verified asynchronously via
    /// `Action::VerifyCycleProof` after structural validation passes. This method
    /// only checks that the proof is present and structurally valid.
    ///
    /// ## Aborts (TransactionAbort)
    /// - ExecutionTimeout: Structural rules only (timeout threshold is proposer's call)
    /// - TooManyRetries: Structural rules only (retry count is in the abort itself)
    fn validate_deferrals_and_aborts(&self, block: &Block) -> Result<(), String> {
        use hyperscale_types::{AbortReason, DeferReason};
        use std::collections::HashSet;

        // Build set of certificate hashes in this block for staleness checks
        let cert_hashes: HashSet<Hash> = block
            .certificates
            .iter()
            .map(|c| c.transaction_hash)
            .collect();

        // Validate each deferral
        for deferral in &block.deferred {
            let DeferReason::LivelockCycle { winner_tx_hash } = &deferral.reason;

            // Rule 1: Hash ordering - deferred TX must have higher hash than winner
            // (Lower hash wins in cycle detection)
            if deferral.tx_hash <= *winner_tx_hash {
                return Err(format!(
                    "Invalid deferral: deferred_hash {} must be > winner_hash {} (lower hash wins)",
                    deferral.tx_hash, winner_tx_hash
                ));
            }

            // Rule 2: Winner not in same block (stale deferral - winner already done)
            if cert_hashes.contains(winner_tx_hash) {
                return Err(format!(
                    "Invalid deferral: winner {} has certificate in same block (stale)",
                    winner_tx_hash
                ));
            }

            // Rule 3: Loser not in same block (stale deferral - loser completed before defer)
            if cert_hashes.contains(&deferral.tx_hash) {
                return Err(format!(
                    "Invalid deferral: deferred TX {} has certificate in same block (stale)",
                    deferral.tx_hash
                ));
            }

            // Rule 4: CycleProof must be present
            // BFT safety: Without a proof, a Byzantine proposer could cause honest validators
            // to incorrectly defer transactions. The proof contains an aggregated BLS signature
            // from the winner's source shard that will be verified asynchronously.

            // Rule 5: CycleProof winner hash must match deferral reason
            if deferral.proof.winner_tx_hash != *winner_tx_hash {
                return Err(format!(
                    "Invalid deferral: CycleProof winner {} != deferral winner {}",
                    deferral.proof.winner_tx_hash, winner_tx_hash
                ));
            }

            // Note: The CycleProof's BLS signature is verified asynchronously via
            // Action::VerifyCycleProof. We only check structural validity here.
            // The signature verification happens after this passes.
        }

        // Validate each abort
        for abort in &block.aborted {
            match &abort.reason {
                AbortReason::ExecutionTimeout { committed_at } => {
                    // Basic sanity: abort block_height must be after committed_at
                    if abort.block_height.0 < committed_at.0 {
                        return Err(format!(
                            "Invalid abort: block_height {} < committed_at {} for timeout",
                            abort.block_height.0, committed_at.0
                        ));
                    }
                    // Note: We don't validate that enough blocks have passed - the proposer
                    // determines the timeout threshold. If we disagree on thresholds, we'd
                    // need configuration consensus, which is out of scope.
                }
                AbortReason::TooManyRetries { retry_count } => {
                    // Sanity: retry count must be positive
                    if *retry_count == 0 {
                        return Err("Invalid abort: TooManyRetries with retry_count 0".to_string());
                    }
                    // Note: We don't validate the actual max_retries threshold - that's
                    // configuration that may differ between nodes.
                }
                AbortReason::ExecutionRejected { .. } => {
                    // No structural validation needed - execution rejection reasons are
                    // determined by the executor
                }
            }
        }

        Ok(())
    }

    /// Validate transaction ordering in a proposed block.
    ///
    /// # Sectioned Block Structure
    ///
    /// Blocks have three explicit transaction sections:
    /// 1. **retry_transactions**: Retry transactions (highest priority)
    /// 2. **priority_transactions**: Cross-shard TXs with CommitmentProof
    /// 3. **transactions**: All other TXs (normal priority)
    ///
    /// Within each section, transactions must be sorted by hash (ascending).
    ///
    /// # Validation Rules
    ///
    /// 1. Each section must be internally hash-sorted
    /// 2. retry_transactions must contain ONLY retry transactions
    /// 3. priority_transactions must contain ONLY non-retry TXs with commitment proofs
    /// 4. transactions must contain no retries and no TXs with commitment proofs
    fn validate_transaction_ordering(&self, block: &Block) -> Result<(), String> {
        // 1. Verify each section is internally hash-sorted
        Self::verify_hash_sorted(&block.retry_transactions, "retry")?;
        Self::verify_hash_sorted(&block.priority_transactions, "priority")?;
        Self::verify_hash_sorted(&block.transactions, "other")?;

        // 2. Verify retry section contains only retry transactions
        for tx in &block.retry_transactions {
            if !tx.is_retry() {
                return Err(format!(
                    "Transaction {} in retry section but is_retry() = false",
                    tx.hash()
                ));
            }
        }

        // 3. Verify priority section contains only non-retry TXs with commitment proofs
        for tx in &block.priority_transactions {
            let tx_hash = tx.hash();
            if tx.is_retry() {
                return Err(format!(
                    "Retry transaction {} in priority section (should be in retry section)",
                    tx_hash
                ));
            }
            if !block.has_commitment_proof(&tx_hash) {
                return Err(format!(
                    "Transaction {} in priority section but has no commitment proof",
                    tx_hash
                ));
            }
        }

        // 4. Verify other section contains no retries and no TXs with proofs
        for tx in &block.transactions {
            let tx_hash = tx.hash();
            if tx.is_retry() {
                return Err(format!(
                    "Retry transaction {} in other section (should be in retry section)",
                    tx_hash
                ));
            }
            if block.has_commitment_proof(&tx_hash) {
                return Err(format!(
                    "Transaction {} has commitment proof but is in other section (should be in priority section)",
                    tx_hash
                ));
            }
        }

        Ok(())
    }

    /// Verify that a list of transactions is sorted by hash in ascending order.
    fn verify_hash_sorted(txs: &[Arc<RoutableTransaction>], section: &str) -> Result<(), String> {
        for window in txs.windows(2) {
            if window[0].hash() >= window[1].hash() {
                return Err(format!(
                    "{} section not in hash order: {} >= {}",
                    section,
                    window[0].hash(),
                    window[1].hash()
                ));
            }
        }
        Ok(())
    }

    /// Create a vote for a block.
    #[tracing::instrument(level = "debug", skip(self), fields(
        height = height,
        round = round,
        sign_us = tracing::field::Empty,
    ))]
    fn create_vote(&mut self, block_hash: Hash, height: u64, round: u64) -> Vec<Action> {
        // Record that we voted for this block at this height.
        // Core safety invariant: we will not vote for a different block at this height
        // unless the vote lock is released on timeout (see `advance_round`) or by
        // QC-based unlock (see `maybe_unlock_for_qc`).
        self.voted_heights.insert(height, (block_hash, round));

        // Create signature with domain separation (prevents cross-shard replay)
        let signing_message =
            Self::block_vote_message(self.shard_group, height, round, &block_hash);
        let sign_start = std::time::Instant::now();
        let signature = self.signing_key.sign_v1(&signing_message);
        tracing::Span::current().record("sign_us", sign_start.elapsed().as_micros() as u64);
        let timestamp = self.now.as_millis() as u64;

        let vote = BlockVote {
            block_hash,
            height: BlockHeight(height),
            round,
            voter: self.validator_id(),
            signature,
            timestamp,
        };

        debug!(
            validator = ?self.validator_id(),
            height = height,
            round = round,
            block_hash = ?block_hash,
            "Created vote"
        );

        // Broadcast vote
        let gossip = hyperscale_messages::BlockVoteGossip { vote: vote.clone() };

        // **BFT Safety Critical**: Persist the vote BEFORE broadcasting.
        // If we crash after broadcasting but before persisting, we could vote
        // for a different block at this height after restart (equivocation).
        // Using the combined action allows the runner to optimize the flow
        // while guaranteeing persist-before-broadcast ordering.
        let mut actions = vec![Action::PersistAndBroadcastVote {
            height: BlockHeight(height),
            round,
            block_hash,
            shard: self.local_shard(),
            vote: gossip,
        }];

        // Also process our own vote locally
        actions.extend(self.on_block_vote_internal(vote));

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote Collection (Deferred Verification)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle received block vote.
    ///
    /// Uses deferred verification: votes are buffered until we have enough
    /// voting power to possibly reach quorum. Only then do we batch-verify
    /// all buffered votes and build the QC in a single operation.
    ///
    /// Note: The sender identity comes from vote.voter (ValidatorId), which is
    /// signed and verified.
    #[instrument(skip(self, vote), fields(
        height = vote.height.0,
        voter = ?vote.voter,
        block_hash = ?vote.block_hash
    ))]
    pub fn on_block_vote(&mut self, vote: BlockVote) -> Vec<Action> {
        trace!(
            validator = ?self.validator_id(),
            voter = ?vote.voter,
            block_hash = ?vote.block_hash,
            "Received block vote"
        );

        self.on_block_vote_internal(vote)
    }

    /// Internal vote processing with deferred verification.
    ///
    /// Buffers votes in VoteSet until we have enough for quorum, then triggers
    /// batch verification + QC building in a single operation.
    ///
    /// For our own vote, we add it directly as verified (we just signed it).
    fn on_block_vote_internal(&mut self, vote: BlockVote) -> Vec<Action> {
        let block_hash = vote.block_hash;
        let height = vote.height.0;
        let is_own_vote = vote.voter == self.validator_id();

        // Early out: skip votes for already-committed heights.
        // This prevents wasting crypto resources verifying stale votes.
        if height <= self.committed_height {
            trace!(
                vote_height = height,
                committed_height = self.committed_height,
                voter = ?vote.voter,
                "Skipping vote for already-committed height"
            );
            return vec![];
        }

        // Validate voter is in committee
        let voter_index = match self.committee_index(vote.voter) {
            Some(idx) => idx,
            None => {
                warn!("Vote from validator {:?} not in committee", vote.voter);
                return vec![];
            }
        };

        // Get voting power
        let voting_power = self.voting_power(vote.voter);
        if voting_power == 0 {
            warn!(
                "Vote from validator {:?} with zero voting power",
                vote.voter
            );
            return vec![];
        }

        // Pre-compute topology values before mutable borrows
        let committee_size = self.committee().len();
        let total_power = self.total_voting_power();
        let validator_id = self.validator_id();
        let header_for_vote = self
            .pending_blocks
            .get(&block_hash)
            .map(|pb| pb.header().clone());

        // Get public key for verification (do this before mutable borrow of vote_sets)
        let public_key = if !is_own_vote {
            match self.public_key(vote.voter) {
                Some(pk) => Some(pk),
                None => {
                    warn!("No public key for validator {:?}", vote.voter);
                    return vec![];
                }
            }
        } else {
            None
        };

        // Get or create vote set
        let vote_set = self
            .vote_sets
            .entry(block_hash)
            .or_insert_with(|| VoteSet::new(header_for_vote, committee_size));

        // Check if already seen
        if vote_set.has_seen_validator(voter_index) {
            trace!("Already seen vote from validator {:?}", vote.voter);
            return vec![];
        }

        // For our own vote, add directly as verified (we just signed it)
        if is_own_vote {
            trace!(
                block_hash = ?block_hash,
                "Adding own vote as verified"
            );
            vote_set.add_verified_vote(voter_index, vote.clone(), voting_power);

            // Check if we should trigger verification for buffered votes
            return self.maybe_trigger_vote_verification(block_hash);
        }

        // Buffer the unverified vote (public_key is guaranteed Some since !is_own_vote)
        let public_key = public_key.unwrap();
        vote_set.buffer_unverified_vote(voter_index, vote, public_key, voting_power);

        trace!(
            validator = ?validator_id,
            block_hash = ?block_hash,
            verified_power = vote_set.verified_power(),
            unverified_power = vote_set.unverified_power(),
            total_power = total_power,
            "Vote buffered"
        );

        // Check if we should trigger batch verification
        self.maybe_trigger_vote_verification(block_hash)
    }

    /// Check if we should trigger batch vote verification for a block.
    ///
    /// Triggers when we have enough total power (verified + unverified) to
    /// possibly reach quorum.
    fn maybe_trigger_vote_verification(&mut self, block_hash: Hash) -> Vec<Action> {
        let total_power = self.total_voting_power();

        let Some(vote_set) = self.vote_sets.get_mut(&block_hash) else {
            return vec![];
        };

        if !vote_set.should_trigger_verification(total_power) {
            return vec![];
        }

        // Get verification data
        let Some((_, height, round, parent_block_hash)) = vote_set.verification_data() else {
            return vec![];
        };

        // Get already-verified votes (e.g., our own vote)
        let verified_votes = vote_set.get_verified_votes();

        // Take the unverified votes
        let votes_to_verify = vote_set.take_unverified_votes();

        // Need at least some votes to verify (verified votes alone would have triggered earlier)
        if votes_to_verify.is_empty() {
            return vec![];
        }

        info!(
            block_hash = ?block_hash,
            height = height.0,
            votes_to_verify = votes_to_verify.len(),
            already_verified = verified_votes.len(),
            "Triggering batch vote verification (quorum possible)"
        );

        // Construct signing message with domain separation
        let signing_message =
            Self::block_vote_message(self.shard_group, height.0, round, &block_hash);

        vec![Action::VerifyAndBuildQuorumCertificate {
            block_hash,
            height,
            round,
            parent_block_hash,
            signing_message,
            votes_to_verify,
            verified_votes,
            total_voting_power: total_power,
        }]
    }

    /// Handle QC verification and building result.
    ///
    /// Called when the runner completes `Action::VerifyAndBuildQuorumCertificate`.
    ///
    /// If QC was built successfully, enqueues QuorumCertificateFormed event.
    /// If quorum wasn't reached (some sigs invalid), adds verified votes back
    /// to VoteSet and checks if more buffered votes can now reach quorum.
    #[instrument(skip(self, qc, verified_votes), fields(
        block_hash = ?block_hash,
        has_qc = qc.is_some(),
        verified_count = verified_votes.len()
    ))]
    pub fn on_qc_result(
        &mut self,
        block_hash: Hash,
        qc: Option<QuorumCertificate>,
        verified_votes: Vec<(usize, BlockVote, u64)>,
    ) -> Vec<Action> {
        // If QC was built successfully, we're done
        if let Some(qc) = qc {
            info!(
                block_hash = ?block_hash,
                height = qc.height.0,
                voting_power = qc.voting_power.0,
                "QC built successfully"
            );

            // Mark vote set as complete
            if let Some(vote_set) = self.vote_sets.get_mut(&block_hash) {
                vote_set.on_qc_built();
            }

            return vec![Action::Continuation(
                ProtocolEvent::QuorumCertificateFormed { block_hash, qc },
            )];
        }

        // Process verified votes: view sync, equivocation detection, and recording.
        //
        // IMPORTANT: Equivocation detection happens AFTER signature verification to prevent
        // a DoS attack where a malicious node forges votes to block legitimate validators.
        // Only verified votes are recorded in received_votes_by_height.
        //
        // TODO: Collect both conflicting votes as slashing proof for economic penalties.
        let validator_id = self.validator_id();
        for (_, vote, _) in &verified_votes {
            // View synchronization
            if vote.round > self.view {
                info!(
                    validator = ?validator_id,
                    old_view = self.view,
                    new_view = vote.round,
                    vote_height = vote.height.0,
                    voter = ?vote.voter,
                    "View synchronization: advancing view to match verified vote"
                );
                self.view = vote.round;
            }

            // Equivocation detection: check if this validator already voted for a DIFFERENT
            // block at the same height AND round. Voting for different blocks at different
            // rounds is allowed (vote lock release on timeout/QC), but same round is Byzantine behavior.
            let vote_key = (vote.height.0, vote.voter);
            if let Some(&(existing_hash, existing_round)) =
                self.received_votes_by_height.get(&vote_key)
            {
                if existing_hash != block_hash && existing_round == vote.round {
                    warn!(
                        voter = ?vote.voter,
                        height = vote.height.0,
                        round = vote.round,
                        existing_block = ?existing_hash,
                        new_block = ?block_hash,
                        "EQUIVOCATION DETECTED: validator voted for different blocks at same height/round"
                    );
                    // This is detection for slashing, not prevention. The equivocating vote
                    // was already counted by the runner (QC may already be built). This is fine:
                    // - BFT safety is guaranteed by quorum intersection, not equivocation prevention
                    // - A Byzantine validator's first vote always gets counted anyway
                    // - The value is in detecting and logging for future slashing
                    continue;
                }
            }

            // Record this verified vote for future equivocation detection
            self.received_votes_by_height
                .insert(vote_key, (block_hash, vote.round));
        }

        // Quorum not reached - add verified votes back and check for more
        let Some(vote_set) = self.vote_sets.get_mut(&block_hash) else {
            warn!(
                block_hash = ?block_hash,
                "QC result received but no vote set found"
            );
            return vec![];
        };

        // Record verified votes
        if !verified_votes.is_empty() {
            vote_set.on_votes_verified(verified_votes);

            info!(
                block_hash = ?block_hash,
                verified_power = vote_set.verified_power(),
                unverified_power = vote_set.unverified_power(),
                "Votes verified but quorum not reached, waiting for more"
            );
        } else {
            warn!(
                block_hash = ?block_hash,
                "All votes failed verification"
            );
            // Clear pending flag so we can try again with new votes
            vote_set.on_votes_verified(vec![]);
        }

        // Check if more unverified votes arrived while we were verifying
        self.maybe_trigger_vote_verification(block_hash)
    }

    /// Handle QC signature verification result.
    ///
    /// Called when the runner completes `Action::VerifyQcSignature`.
    /// If valid, we proceed to vote on the block (for consensus) or apply the block (for sync).
    #[instrument(skip(self), fields(block_hash = ?block_hash, valid = valid))]
    pub fn on_qc_signature_verified(&mut self, block_hash: Hash, valid: bool) -> Vec<Action> {
        // Check if this is a synced block verification
        info!(
            block_hash = ?block_hash,
            valid,
            pending_sync_count = self.pending_synced_block_verifications.len(),
            pending_consensus_count = self.pending_qc_verifications.len(),
            "on_qc_signature_verified: received callback"
        );
        if let Some(mut pending_sync) = self.pending_synced_block_verifications.remove(&block_hash)
        {
            if !valid {
                warn!(
                    block_hash = ?block_hash,
                    height = pending_sync.block.header.height.0,
                    "Synced block QC signature verification FAILED - rejecting block"
                );
                // Clear all pending synced blocks since chain is broken
                self.pending_synced_block_verifications.clear();
                return vec![];
            }

            info!(
                block_hash = ?block_hash,
                height = pending_sync.block.header.height.0,
                "Synced block QC verified successfully"
            );

            // Mark this block as verified
            pending_sync.verified = true;

            // Put it back temporarily to check ordering
            self.pending_synced_block_verifications
                .insert(block_hash, pending_sync);

            // Try to apply all consecutive verified blocks starting from committed_height + 1
            return self.try_apply_verified_synced_blocks();
        }

        // Otherwise, it's a consensus block QC verification
        let Some(pending) = self.pending_qc_verifications.remove(&block_hash) else {
            warn!(
                "QC signature verified but no pending verification for block {}",
                block_hash
            );
            return vec![];
        };

        // Check verification result
        if !valid {
            warn!(
                block_hash = ?block_hash,
                height = pending.header.height.0,
                "QC signature verification FAILED - potential Byzantine attack! Rejecting block."
            );
            // Remove the pending block since we can't trust it
            self.pending_blocks.remove(&block_hash);
            return vec![];
        }

        debug!(
            block_hash = ?block_hash,
            height = pending.header.height.0,
            "QC signature verified successfully, proceeding to vote"
        );

        // Cache the verified QC so we don't re-verify it for other blocks
        // with the same parent_qc (e.g., during view changes).
        let qc_block_hash = pending.header.parent_qc.block_hash;
        let qc_height = pending.header.parent_qc.height.0;
        self.verified_qcs.insert(qc_block_hash, qc_height);
        trace!(
            qc_block_hash = ?qc_block_hash,
            qc_height = qc_height,
            "Cached verified QC"
        );

        // QC is valid - proceed to vote on the block
        let height = pending.header.height.0;
        let round = pending.header.round;
        self.try_vote_on_block(block_hash, height, round)
    }

    /// Handle CycleProof signature verification result.
    ///
    /// Called when the runner completes `Action::VerifyCycleProof`.
    /// If all proofs are valid, we proceed to vote on the block.
    /// If any proof is invalid, the block is rejected.
    #[instrument(skip(self), fields(block_hash = ?block_hash, deferral_index = deferral_index, valid = valid))]
    pub fn on_cycle_proof_verified(
        &mut self,
        block_hash: Hash,
        deferral_index: usize,
        valid: bool,
    ) -> Vec<Action> {
        let pending = match self.pending_cycle_proof_verifications.get_mut(&block_hash) {
            Some(p) => p,
            None => {
                warn!(
                    block_hash = ?block_hash,
                    "CycleProof verification result for unknown block"
                );
                return vec![];
            }
        };

        pending.verified += 1;

        if !valid {
            pending.all_valid = false;
            warn!(
                block_hash = ?block_hash,
                deferral_index = deferral_index,
                "CycleProof signature verification FAILED - potential Byzantine attack!"
            );
        } else {
            trace!(
                block_hash = ?block_hash,
                deferral_index = deferral_index,
                "CycleProof verified successfully"
            );
        }

        // Check if all verifications are complete
        if pending.verified < pending.total {
            trace!(
                block_hash = ?block_hash,
                verified = pending.verified,
                total = pending.total,
                "Waiting for more CycleProof verifications"
            );
            return vec![];
        }

        // All verifications complete
        let all_valid = pending.all_valid;
        self.pending_cycle_proof_verifications.remove(&block_hash);

        if !all_valid {
            info!(
                block_hash = ?block_hash,
                "Block rejected due to invalid CycleProof(s)"
            );
            // Remove the pending block since we can't trust it
            self.pending_blocks.remove(&block_hash);
            return vec![];
        }

        self.verified_cycle_proofs.insert(block_hash);

        debug!(
            block_hash = ?block_hash,
            "All CycleProofs verified successfully"
        );
        let Some(pending_block) = self.pending_blocks.get(&block_hash) else {
            warn!(
                block_hash = ?block_hash,
                "CycleProof verification complete but pending block not found"
            );
            return vec![];
        };

        let block = match pending_block.block() {
            Some(b) => b,
            None => return vec![],
        };

        // Check if all verifications are complete (state root may still be pending)
        if !self.block_verifications_complete(&block) {
            debug!(
                block_hash = ?block_hash,
                "CycleProofs done, waiting for other verifications"
            );
            return vec![];
        }

        let height = pending_block.header().height.0;
        let round = pending_block.header().round;

        // All verifications complete - vote
        self.create_vote(block_hash, height, round)
    }

    /// Handle state root verification result.
    ///
    /// Called when the runner completes `Action::VerifyStateRoot`. If the state root
    /// is invalid, the block is rejected (proposer included incorrect state commitment).
    /// If valid, proceeds to vote for the block.
    #[instrument(skip(self), fields(block_hash = ?block_hash, valid = valid))]
    pub fn on_state_root_verified(&mut self, block_hash: Hash, valid: bool) -> Vec<Action> {
        // Remove from in-flight regardless of outcome
        self.state_root_verifications_in_flight.remove(&block_hash);

        if !valid {
            warn!(
                block_hash = ?block_hash,
                "State root verification FAILED - proposer included incorrect state_root!"
            );
            // Remove the pending block since the proposer lied about state
            self.pending_blocks.remove(&block_hash);
            return vec![];
        }

        self.verified_state_roots.insert(block_hash);

        debug!(
            block_hash = ?block_hash,
            "State root verified successfully"
        );
        let Some(pending_block) = self.pending_blocks.get(&block_hash) else {
            warn!(
                block_hash = ?block_hash,
                "State root verification complete but pending block not found"
            );
            return vec![];
        };

        let block = match pending_block.block() {
            Some(b) => b,
            None => return vec![],
        };

        // Check if all verifications are complete (cycle proofs may still be pending)
        if !self.block_verifications_complete(&block) {
            debug!(
                block_hash = ?block_hash,
                "State root done, waiting for other verifications"
            );
            return vec![];
        }

        let height = pending_block.header().height.0;
        let round = pending_block.header().round;

        // All verifications complete - vote
        self.create_vote(block_hash, height, round)
    }

    /// Check if a block needs transaction root verification before voting.
    ///
    /// Returns true if the block has transactions and we haven't already verified
    /// or initiated verification.
    fn block_needs_transaction_root_verification(&self, block: &Block) -> bool {
        if block.transaction_count() == 0 {
            return false;
        }

        let block_hash = block.hash();

        // Skip if already verified or in-flight
        if self.verified_transaction_roots.contains(&block_hash)
            || self
                .transaction_root_verifications_in_flight
                .contains(&block_hash)
        {
            return false;
        }

        true
    }

    /// Initiate transaction root verification for a block.
    ///
    /// Unlike state root verification, this doesn't depend on JMT state and can
    /// be verified immediately. This runs in parallel with state root and cycle
    /// proof verifications.
    fn initiate_transaction_root_verification(
        &mut self,
        block_hash: Hash,
        block: &Block,
    ) -> Vec<Action> {
        debug!(
            block_hash = ?block_hash,
            retry_count = block.retry_transactions.len(),
            priority_count = block.priority_transactions.len(),
            tx_count = block.transactions.len(),
            expected_root = ?block.header.transaction_root,
            "Initiating transaction root verification"
        );

        self.transaction_root_verifications_in_flight
            .insert(block_hash);

        vec![Action::VerifyTransactionRoot {
            block_hash,
            expected_root: block.header.transaction_root,
            retry_transactions: block.retry_transactions.clone(),
            priority_transactions: block.priority_transactions.clone(),
            transactions: block.transactions.clone(),
        }]
    }

    /// Handle transaction root verification result.
    ///
    /// Called when the runner completes `Action::VerifyTransactionRoot`. If the
    /// transaction root is invalid, the block is rejected. If valid, proceeds to
    /// vote for the block (assuming other verifications are also complete).
    #[instrument(skip(self), fields(block_hash = ?block_hash, valid = valid))]
    pub fn on_transaction_root_verified(&mut self, block_hash: Hash, valid: bool) -> Vec<Action> {
        // Remove from in-flight regardless of outcome
        self.transaction_root_verifications_in_flight
            .remove(&block_hash);

        if !valid {
            warn!(
                block_hash = ?block_hash,
                "Transaction root verification FAILED - proposer included incorrect transaction_root!"
            );
            // Remove the pending block since the proposer lied about transactions
            self.pending_blocks.remove(&block_hash);
            return vec![];
        }

        self.verified_transaction_roots.insert(block_hash);

        debug!(
            block_hash = ?block_hash,
            "Transaction root verified successfully"
        );

        let Some(pending_block) = self.pending_blocks.get(&block_hash) else {
            warn!(
                block_hash = ?block_hash,
                "Transaction root verification complete but pending block not found"
            );
            return vec![];
        };

        let block = match pending_block.block() {
            Some(b) => b,
            None => return vec![],
        };

        // Check if all verifications are complete (state root, cycle proofs may still be pending)
        if !self.block_verifications_complete(&block) {
            debug!(
                block_hash = ?block_hash,
                "Transaction root done, waiting for other verifications"
            );
            return vec![];
        }

        let height = pending_block.header().height.0;
        let round = pending_block.header().round;

        // All verifications complete - vote
        self.create_vote(block_hash, height, round)
    }

    /// Handle proposal built by the runner.
    ///
    /// Called when the runner completes `Action::BuildProposal`. The runner has
    /// computed the state root, built the complete block, and cached the WriteBatch
    /// for efficient commit later.
    #[instrument(skip(self, block), fields(height = %height.0, round = round))]
    pub fn on_proposal_built(
        &mut self,
        height: BlockHeight,
        round: u64,
        block: Arc<Block>,
        block_hash: Hash,
    ) -> Vec<Action> {
        // Take the pending proposal - if it doesn't match (height, round), something is wrong
        let Some(pending) = self.pending_proposal.take() else {
            warn!(
                height = height.0,
                round = round,
                "ProposalBuilt received but no pending proposal"
            );
            return vec![];
        };

        if pending.height != height || pending.round != round {
            warn!(
                expected_height = pending.height.0,
                expected_round = pending.round,
                received_height = height.0,
                received_round = round,
                "ProposalBuilt mismatch - discarding stale result"
            );
            // Put back the pending proposal if it's different (shouldn't happen)
            self.pending_proposal = Some(pending);
            return vec![];
        }

        let has_certificates = !block.certificates.is_empty();

        // Build hashes for gossip and pending block
        let retry_hashes: Vec<Hash> = block
            .retry_transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();
        let priority_hashes: Vec<Hash> = block
            .priority_transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();
        let tx_hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();
        let cert_hashes: Vec<Hash> = block
            .certificates
            .iter()
            .map(|c| c.transaction_hash)
            .collect();

        let total_tx_count = retry_hashes.len() + priority_hashes.len() + tx_hashes.len();
        info!(
            validator = ?self.validator_id(),
            height = height.0,
            round = round,
            block_hash = ?block_hash,
            transactions = total_tx_count,
            certificates = cert_hashes.len(),
            has_certificates = has_certificates,
            "Broadcasting proposal"
        );

        // Store our own block as pending (already complete)
        let mut pending_block = PendingBlock::with_proofs(
            block.header.clone(),
            retry_hashes.clone(),
            priority_hashes.clone(),
            tx_hashes.clone(),
            cert_hashes.clone(),
            block.deferred.clone(),
            block.aborted.clone(),
            block.commitment_proofs.clone(),
        );

        for tx in &block.retry_transactions {
            pending_block.add_transaction_arc(Arc::clone(tx));
        }
        for tx in &block.priority_transactions {
            pending_block.add_transaction_arc(Arc::clone(tx));
        }
        for tx in &block.transactions {
            pending_block.add_transaction_arc(Arc::clone(tx));
        }
        for cert in &block.certificates {
            pending_block.add_certificate(Arc::clone(cert));
        }

        if let Err(e) = pending_block.construct_block() {
            warn!("Failed to construct own proposal block: {}", e);
            return vec![];
        }

        self.pending_blocks.insert(block_hash, pending_block);
        self.pending_block_created_at.insert(block_hash, self.now);
        self.last_proposal_time = self.now;
        self.record_leader_activity();

        // Build gossip message with complete block data
        let gossip = hyperscale_messages::BlockHeaderGossip {
            header: block.header.clone(),
            retry_hashes,
            priority_hashes,
            transaction_hashes: tx_hashes,
            certificate_hashes: cert_hashes,
            deferred: block.deferred.clone(),
            aborted: block.aborted.clone(),
            commitment_proofs: block.commitment_proofs.clone(),
        };

        let mut actions = vec![Action::BroadcastBlockHeader {
            shard: self.local_shard(),
            header: Box::new(gossip),
        }];

        // Vote for our own block
        actions.extend(self.create_vote(block_hash, height.0, round));

        actions
    }

    /// Handle JMT state commit completion.
    ///
    /// Called when the runner has finished committing a block's state to the JMT.
    /// This updates our tracked local JMT state (last_committed_jmt_state) and
    /// checks if any pending state root verifications can now proceed.
    ///
    /// NOTE: This does NOT update last_chain_committed_state_version. That field
    /// is updated synchronously when blocks commit (in commit_block_and_buffered)
    /// to ensure all validators use the same base version for proposals. The JMT
    /// state tracked here may lag behind the chain-committed version due to async
    /// commit timing, which is fine - verifications are queued until JMT catches up.
    ///
    /// # Arguments
    /// * `state_version` - The JMT version after the commit
    /// * `state_root` - The JMT root hash after the commit
    ///
    /// # Returns
    /// Actions to verify any state roots that were waiting for this commit.
    #[instrument(skip(self), fields(validator = ?self.validator_id()))]
    pub fn on_state_commit_complete(
        &mut self,
        state_version: u64,
        state_root: Hash,
    ) -> Vec<Action> {
        let (current_version, _) = self.last_committed_jmt_state;

        // Only advance version forward (avoid out-of-order updates)
        if state_version <= current_version {
            return vec![];
        }

        debug!(
            old_version = current_version,
            new_version = state_version,
            new_root = ?state_root,
            pending_verifications = self.pending_state_root_verifications.len(),
            "JMT state commit complete, checking for unblocked verifications"
        );

        self.last_committed_jmt_state = (state_version, state_root);

        // NOTE: We do NOT update last_chain_committed_state_version here.
        // That field is updated synchronously in commit_block_and_buffered() when
        // blocks commit. It tracks the CHAIN's committed state (from block headers),
        // not the JMT's async commit state.
        //
        // This function only updates last_committed_jmt_state, which is used to
        // check if JMT has caught up enough for verification to proceed.

        // Find all pending verifications where the JMT now has the required base root.
        // We compare roots, not versions, because that's what guarantees both proposer
        // and verifier compute from the same base state.
        let unblocked: Vec<Hash> = self
            .pending_state_root_verifications
            .iter()
            .filter(|(_, pv)| pv.required_root == state_root)
            .map(|(hash, _)| *hash)
            .collect();

        if unblocked.is_empty() {
            return vec![];
        }

        debug!(
            unblocked_count = unblocked.len(),
            "Unblocking pending state root verifications"
        );

        // Move unblocked verifications from pending to in-flight and emit actions
        let mut actions = Vec::new();
        for block_hash in unblocked {
            if let Some(pv) = self.pending_state_root_verifications.remove(&block_hash) {
                self.state_root_verifications_in_flight.insert(block_hash);
                actions.push(Action::VerifyStateRoot {
                    block_hash,
                    parent_state_root: pv.required_root,
                    expected_root: pv.expected_root,
                    certificates: pv.certificates,
                });
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // QC and Commit Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /// Count transactions and certificates in the block that would be committed by a QC.
    ///
    /// This is used by the mempool to account for "about to be committed" transactions
    /// when calculating in-flight limits. When a QC forms, the 2-chain commit rule
    /// may commit a parent block, but that commit event won't be processed until after
    /// transaction selection. This method allows the caller to preemptively count:
    /// - Transactions that will INCREASE in-flight (new commits)
    /// - Certificates that will DECREASE in-flight (completed transactions)
    ///
    /// Returns (tx_count, cert_count). Both are 0 if the QC won't trigger a commit
    /// or the block data isn't available.
    pub fn pending_commit_counts(&self, qc: &QuorumCertificate) -> (usize, usize) {
        if !qc.has_committable_block() {
            return (0, 0);
        }

        let Some(committable_hash) = qc.committable_hash() else {
            return (0, 0);
        };
        let Some(committable_height) = qc.committable_height() else {
            return (0, 0);
        };

        // Only count if we haven't already committed this height
        if committable_height.0 <= self.committed_height {
            return (0, 0);
        }

        // Look up the block to count transactions and certificates
        if let Some(pending) = self.pending_blocks.get(&committable_hash) {
            if let Some(block) = pending.block() {
                (block.transactions.len(), block.certificates.len())
            } else {
                (0, 0)
            }
        } else if let Some((block, _)) = self.certified_blocks.get(&committable_hash) {
            (block.transactions.len(), block.certificates.len())
        } else {
            (0, 0)
        }
    }

    /// Count transactions and certificates in ALL pending blocks above committed height.
    ///
    /// This accounts for pipelining in chained BFT: multiple blocks can be proposed
    /// before the first one commits. Each pending block's transactions will increase
    /// in-flight when they commit, and each pending block's certificates will decrease
    /// in-flight.
    ///
    /// Returns (total_tx_count, total_cert_count) across all pending blocks.
    pub fn pending_block_tx_cert_counts(&self) -> (usize, usize) {
        let mut total_txs = 0;
        let mut total_certs = 0;

        for pending in self.pending_blocks.values() {
            // Use original_tx_order/original_cert_order which are available even
            // before the block is fully constructed (waiting for tx/cert data).
            // These give us the counts from the block header.
            total_txs += pending.all_transaction_hashes().len();
            total_certs += pending.all_certificate_hashes().len();
        }

        (total_txs, total_certs)
    }

    /// Handle QC formation.
    ///
    /// When a QC forms, we:
    /// 1. Update our latest QC
    /// 2. Check if any blocks can be committed (two-chain rule)
    /// 3. Immediately try to propose the next block if we're the proposer
    ///
    /// Step 3 is critical for chain progress: without it, the chain would stall
    /// waiting for the next proposal timer, but the designated proposer for the
    /// next height might not know about this QC yet.
    ///
    /// # State Root Parameter
    ///
    /// `state_root` is the computed JMT root after applying writes from the certificates.
    /// If certificates is empty, this is ignored and parent state is inherited.
    /// `state_version` is derived from chain history (parent.state_version + certificates.len())
    /// to avoid race conditions with async JMT commits.
    #[instrument(skip(self, qc, ready_txs, deferred, aborted, certificates, commitment_proofs), fields(
        height = qc.height.0,
        block_hash = ?block_hash
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_qc_formed(
        &mut self,
        block_hash: Hash,
        qc: QuorumCertificate,
        ready_txs: &ReadyTransactions,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        certificates: Vec<Arc<TransactionCertificate>>,
        commitment_proofs: HashMap<Hash, CommitmentProof>,
    ) -> Vec<Action> {
        let height = qc.height.0;

        info!(
            validator = ?self.validator_id(),
            block_hash = ?block_hash,
            height = height,
            "QC formed"
        );

        // Record leader activity - QC forming indicates progress
        self.record_leader_activity();

        // Update latest QC if this is newer
        let should_update = self
            .latest_qc
            .as_ref()
            .is_none_or(|existing| qc.height.0 > existing.height.0);

        if should_update {
            self.latest_qc = Some(qc.clone());

            // HotStuff-2 unlock: when a QC forms, we can safely unlock
            // our vote locks at or below that QC's height
            self.maybe_unlock_for_qc(&qc);
        }

        let mut actions = vec![];

        // Persist the certified block immediately so it's available for sync.
        // In HotStuff-2, block N gets certified (QC formed) before it's committed
        // (which happens when block N+1 gets certified). If we only persist on commit,
        // there's a window where the QC exists but the block isn't in storage,
        // causing sync failures when other validators try to fetch it.
        let block = if let Some(pending) = self.pending_blocks.get(&block_hash) {
            pending.block().map(|b| (*b).clone())
        } else if let Some((block, _)) = self.certified_blocks.get(&block_hash) {
            Some(block.clone())
        } else {
            None
        };

        if let Some(block) = block {
            debug!(
                validator = ?self.validator_id(),
                height = height,
                block_hash = ?block_hash,
                "Persisting certified block for sync availability"
            );
            actions.push(Action::PersistBlock {
                block,
                qc: qc.clone(),
            });
        } else {
            // Block not yet complete - this can happen if we're still fetching
            // transactions/certificates. The block will be persisted when it commits.
            debug!(
                validator = ?self.validator_id(),
                height = height,
                block_hash = ?block_hash,
                "Cannot persist certified block - not yet complete"
            );
        }

        // Two-chain commit rule: when we have QC for block N,
        // we can commit block N-1 (the parent)
        if qc.has_committable_block() {
            if let (Some(committable_height), Some(committable_hash)) =
                (qc.committable_height(), qc.committable_hash())
            {
                // Only commit if we haven't already committed this height
                if committable_height.0 > self.committed_height {
                    actions.push(Action::Continuation(ProtocolEvent::BlockReadyToCommit {
                        block_hash: committable_hash,
                        qc: qc.clone(),
                    }));
                }
            }
        }

        // Immediately try to propose the next block if there's content to include.
        // This is how the QC propagates to other validators - the next block
        // header will include this QC as parent_qc.
        //
        // We only propose immediately if there's actual content (transactions,
        // deferrals, aborts, or certificates). Empty blocks provide no value and
        // just waste resources on signature verification and storage. If there's
        // nothing to include, the regular proposal timer will fire and propagate
        // the QC then.
        //
        // Rate limiting: Even with content, we respect min_block_interval to prevent
        // burst behavior under high load. If we proposed too recently, let the
        // regular proposal timer handle it.
        let next_height = height + 1;

        let has_content = !ready_txs.is_empty()
            || !deferred.is_empty()
            || !aborted.is_empty()
            || !certificates.is_empty();

        let time_since_last_proposal = self.now.saturating_sub(self.last_proposal_time);
        let rate_limited = time_since_last_proposal < self.config.min_block_interval;

        // Attempt immediate proposal if:
        // - We have content to include, OR
        // - We're syncing (should propose empty sync blocks to keep chain advancing)
        //
        // All other checks (should_propose, backpressure, voted_heights)
        // are handled inside on_proposal_timer to avoid duplication.
        let should_try_proposal = has_content || self.syncing;

        if should_try_proposal && !rate_limited {
            // on_proposal_timer will check if we're the proposer, backpressure, etc.
            // State root is computed by NodeStateMachine and passed in.
            // If certificates is empty, on_proposal_timer will inherit parent state.
            // State version is derived from chain history inside on_proposal_timer.
            actions.extend(self.on_proposal_timer(
                ready_txs,
                deferred,
                aborted,
                certificates,
                commitment_proofs,
            ));
        } else if should_try_proposal && rate_limited {
            trace!(
                validator = ?self.validator_id(),
                next_height = next_height,
                time_since_last_ms = time_since_last_proposal.as_millis(),
                min_interval_ms = self.config.min_block_interval.as_millis(),
                "Rate limiting immediate proposal after QC - waiting for proposal timer"
            );
        }

        actions
    }

    /// Handle block ready to commit.
    #[instrument(skip(self, qc), fields(
        height = qc.height.0,
        block_hash = ?block_hash
    ))]
    pub fn on_block_ready_to_commit(
        &mut self,
        block_hash: Hash,
        qc: QuorumCertificate,
    ) -> Vec<Action> {
        // Get the block to commit
        let block = if let Some(pending) = self.pending_blocks.get(&block_hash) {
            pending.block().map(|b| (*b).clone())
        } else if let Some((block, _)) = self.certified_blocks.get(&block_hash) {
            Some(block.clone())
        } else {
            None
        };

        let Some(block) = block else {
            // Block not yet constructed - check if it's pending (waiting for transactions/certificates)
            if let Some(pending) = self.pending_blocks.get(&block_hash) {
                let height = pending.header().height.0;
                // Only buffer if not already committed
                if height > self.committed_height {
                    debug!(
                        validator = ?self.validator_id(),
                        block_hash = ?block_hash,
                        height = height,
                        missing_txs = pending.missing_transaction_count(),
                        missing_certs = pending.missing_certificate_count(),
                        "Block not yet complete, buffering commit until data arrives"
                    );
                    self.pending_commits_awaiting_data
                        .insert(block_hash, (height, qc));
                }
            } else {
                // Block not in pending_blocks - check if it's in certified_blocks
                let in_certified = self.certified_blocks.contains_key(&block_hash);
                warn!(
                    validator = ?self.validator_id(),
                    block_hash = ?block_hash,
                    qc_height = qc.height.0,
                    committed_height = self.committed_height,
                    in_certified_blocks = in_certified,
                    certified_blocks_count = self.certified_blocks.len(),
                    pending_blocks_count = self.pending_blocks.len(),
                    "Block not found for commit"
                );
            }
            return vec![];
        };

        let height = block.header.height.0;

        // Check if we've already committed this or higher
        if height <= self.committed_height {
            trace!(
                "Block {} at height {} already committed",
                block_hash,
                height
            );
            return vec![];
        }

        // Buffer out-of-order commits for later processing
        // This handles the case where signature verification completes out of order,
        // causing BlockReadyToCommit events to arrive non-sequentially.
        if height != self.committed_height + 1 {
            debug!(
                "Buffering out-of-order commit: expected height {}, got {}",
                self.committed_height + 1,
                height
            );
            self.pending_commits.insert(height, (block_hash, qc));
            return vec![];
        }

        // Commit this block and any buffered subsequent blocks
        self.commit_block_and_buffered(block_hash)
    }

    /// Check if a block that just became complete has a pending commit waiting for it.
    ///
    /// When `BlockReadyToCommit` fires but the block data (transactions/certificates) hasn't
    /// arrived yet, we buffer the commit in `pending_commits_awaiting_data`. This method
    /// checks that buffer and retries the commit now that the block is complete.
    fn try_commit_pending_data(&mut self, block_hash: Hash) -> Vec<Action> {
        if let Some((height, qc)) = self.pending_commits_awaiting_data.remove(&block_hash) {
            info!(
                validator = ?self.validator_id(),
                block_hash = ?block_hash,
                height = height,
                "Retrying commit after block data arrived"
            );
            self.on_block_ready_to_commit(block_hash, qc)
        } else {
            vec![]
        }
    }

    /// Commit a block and any buffered subsequent blocks that are now ready.
    ///
    /// This is called when we have a block at the expected height (committed_height + 1).
    /// After committing, we check for buffered commits at the next height and process
    /// them in order.
    fn commit_block_and_buffered(&mut self, block_hash: Hash) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut current_hash = block_hash;

        loop {
            // Get the block and its certifying QC.
            // Check certified_blocks first since committed blocks should always
            // have a QC (they were certified before commit in the two-chain rule).
            let (block, qc) = if let Some((block, qc)) = self.certified_blocks.get(&current_hash) {
                (Some(block.clone()), Some(qc.clone()))
            } else if let Some(pending) = self.pending_blocks.get(&current_hash) {
                // Fallback: block in pending_blocks but not certified_blocks.
                // This shouldn't happen for committed blocks but handle gracefully.
                warn!(
                    block_hash = ?current_hash,
                    "Committed block not found in certified_blocks - QC unavailable"
                );
                (pending.block().map(|b| (*b).clone()), None)
            } else {
                (None, None)
            };

            let Some(block) = block else {
                warn!("Block {} not found for commit", current_hash);
                break;
            };

            let height = block.header.height.0;

            // Safety check - should always be the next expected height
            if height != self.committed_height + 1 {
                warn!(
                    "Unexpected height in commit_block_and_buffered: expected {}, got {}",
                    self.committed_height + 1,
                    height
                );
                break;
            }

            info!(
                validator = ?self.validator_id(),
                height = height,
                block_hash = ?current_hash,
                transactions = block.transactions.len(),
                "Committing block"
            );

            // Update committed state
            self.committed_height = height;
            self.committed_hash = current_hash;

            // Update chain-committed state version from the committed block's header.
            //
            // CRITICAL: This must be updated SYNCHRONOUSLY when a block commits.
            // This value is used as the base for proposals, ensuring verifiers can
            // always reach the required_base_version (because it's based on actually
            // committed blocks, not speculative QC chain).
            //
            // The StateCommitComplete event still updates last_committed_jmt_state
            // separately, which is used to check if JMT has caught up for verification.
            self.last_chain_committed_state_version = block.header.state_version;

            // Reset backoff tracking - new height means fresh round counting
            self.view_at_height_start = self.view;

            // Record leader activity - block committing indicates progress
            self.record_leader_activity();

            // Clean up old state
            let removed_blocks = self.cleanup_old_state(height);

            // Cancel any pending fetches for removed blocks
            for block_hash in removed_blocks {
                actions.push(Action::CancelFetch { block_hash });
            }

            actions.push(Action::EmitCommittedBlock {
                block: block.clone(),
                qc: qc.unwrap_or_else(QuorumCertificate::genesis),
            });
            actions.push(Action::Continuation(ProtocolEvent::BlockCommitted {
                block_hash: current_hash,
                height,
                block: block.clone(),
            }));

            // Check if the next height is buffered
            let next_height = height + 1;
            if let Some((next_hash, _next_qc)) = self.pending_commits.remove(&next_height) {
                debug!(
                    "Processing buffered commit for height {} after committing {}",
                    next_height, height
                );
                current_hash = next_hash;
            } else {
                // No more buffered commits
                break;
            }
        }

        // After consensus commits, try to drain buffered synced blocks.
        // Consensus may have committed blocks that sync was waiting for,
        // so now those buffered synced blocks may be ready for verification.
        actions.extend(self.try_drain_buffered_synced_blocks());

        actions
    }

    /// Handle a synced block that's ready to be applied.
    ///
    /// This is for blocks fetched via sync protocol, not blocks we participated
    /// in consensus for. We verify the QC signature before applying.
    ///
    /// Blocks may arrive out of order from concurrent fetches. Out-of-order blocks
    /// are buffered and processed once earlier blocks complete verification.
    #[instrument(skip(self, block, qc), fields(
        height = block.header.height.0,
        block_hash = ?block.hash()
    ))]
    fn on_synced_block_ready(&mut self, block: Block, qc: QuorumCertificate) -> Vec<Action> {
        let block_hash = block.hash();
        let height = block.header.height.0;

        info!(
            height,
            block_hash = ?block_hash,
            committed_height = self.committed_height,
            pending_verifications = self.pending_synced_block_verifications.len(),
            buffered_blocks = self.buffered_synced_blocks.len(),
            "Received synced block"
        );

        // Check if we've already committed this or higher
        if height <= self.committed_height {
            info!(
                height,
                committed = self.committed_height,
                "Synced block already committed - filtering"
            );
            return vec![];
        }

        // Verify QC matches block (do this early, before buffering)
        if qc.block_hash != block_hash {
            warn!(
                "Synced block QC mismatch: block_hash {:?} != qc.block_hash {:?}",
                block_hash, qc.block_hash
            );
            return vec![];
        }

        // Check if we already have this block pending or buffered
        if self
            .pending_synced_block_verifications
            .contains_key(&block_hash)
        {
            info!(
                height,
                "Synced block already pending verification - filtering"
            );
            return vec![];
        }
        if self.buffered_synced_blocks.contains_key(&height) {
            info!(height, "Synced block already buffered - filtering");
            return vec![];
        }

        // Calculate what height we need next for sequential application.
        // We need the lowest height that's not yet pending or buffered.
        let next_needed = self.committed_height + 1;

        // Check if this block is the next one we need
        if height == next_needed {
            // This is exactly what we need - submit for verification immediately
            return self.submit_synced_block_for_verification(block, qc);
        }

        // Block is not the next sequential height. Check if we should buffer it
        // or if we already have what we need and should try draining buffers.
        if height > next_needed {
            // Future block - buffer it for later
            debug!(
                height,
                next_needed, "Buffering future synced block for later"
            );
            self.buffered_synced_blocks.insert(height, (block, qc));

            // Check if we can drain any buffered blocks starting from next_needed
            return self.try_drain_buffered_synced_blocks();
        }

        // height < next_needed but > committed_height - this shouldn't happen
        // if the checks above are correct, but handle gracefully
        debug!(
            height,
            next_needed,
            committed = self.committed_height,
            "Unexpected synced block height - already have or past this"
        );
        vec![]
    }

    /// Submit a synced block for QC signature verification.
    ///
    /// Called for in-order blocks or when draining the buffer.
    fn submit_synced_block_for_verification(
        &mut self,
        block: Block,
        qc: QuorumCertificate,
    ) -> Vec<Action> {
        let block_hash = block.hash();
        let height = block.header.height.0;

        // Genesis QC doesn't need signature verification
        if qc.is_genesis() {
            debug!(height, "Synced block has genesis QC, applying directly");
            return self.apply_synced_block(block, qc);
        }

        // Collect public keys for QC verification
        let Some(public_keys) = self.collect_qc_signer_keys(&qc) else {
            warn!("Failed to collect public keys for synced block QC verification");
            return vec![];
        };

        info!(
            height,
            block_hash = ?block_hash,
            signers = qc.signers.count(),
            "Submitting synced block for QC verification"
        );

        // Store pending verification info
        info!(
            height,
            block_hash = ?block_hash,
            "Inserting into pending_synced_block_verifications"
        );
        self.pending_synced_block_verifications.insert(
            block_hash,
            PendingSyncedBlockVerification {
                block,
                qc: qc.clone(),
                verified: false,
            },
        );

        // Construct signing message with domain separation
        let signing_message =
            Self::block_vote_message(self.shard_group, qc.height.0, qc.round, &qc.block_hash);

        // Delegate verification to runner
        vec![Action::VerifyQcSignature {
            qc,
            public_keys,
            block_hash,
            signing_message,
        }]
    }

    /// Try to drain buffered synced blocks in sequential order.
    ///
    /// This is called when a new block is buffered to check if we already have
    /// the next needed block in the buffer.
    ///
    /// We submit up to `max_parallel_sync_verifications` blocks for parallel QC
    /// verification. This allows sync to make progress on multiple blocks at once
    /// instead of waiting for each block to verify sequentially.
    fn try_drain_buffered_synced_blocks(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();

        // How many blocks are already pending verification?
        let pending_count = self.pending_synced_block_verifications.len();

        // Limit parallel verifications to avoid overwhelming the crypto pool.
        // This also bounds memory usage from buffered blocks.
        const MAX_PARALLEL_SYNC_VERIFICATIONS: usize = 16;

        if pending_count >= MAX_PARALLEL_SYNC_VERIFICATIONS {
            // Already at max parallel verifications, wait for some to complete
            return actions;
        }

        let slots_available = MAX_PARALLEL_SYNC_VERIFICATIONS - pending_count;

        // Find the next height we need - accounting for what's already pending verification
        let highest_pending_height = self
            .pending_synced_block_verifications
            .values()
            .map(|p| p.block.header.height.0)
            .max()
            .unwrap_or(self.committed_height);

        let mut next_height = highest_pending_height.max(self.committed_height) + 1;
        let mut submitted = 0;

        // Keep draining as long as we have the next sequential block buffered
        // and haven't hit the parallel verification limit
        while submitted < slots_available {
            if let Some((block, qc)) = self.buffered_synced_blocks.remove(&next_height) {
                debug!(height = next_height, "Draining buffered synced block");
                actions.extend(self.submit_synced_block_for_verification(block, qc));
                next_height += 1;
                submitted += 1;
            } else {
                break;
            }
        }

        actions
    }

    /// Apply a synced block after QC verification (or for genesis QC).
    fn apply_synced_block(&mut self, block: Block, qc: QuorumCertificate) -> Vec<Action> {
        let block_hash = block.hash();
        let height = block.header.height.0;

        info!(
            validator = ?self.validator_id(),
            height = height,
            block_hash = ?block_hash,
            transactions = block.transactions.len(),
            "Applying synced block"
        );

        // Update committed state
        self.committed_height = height;
        self.committed_hash = block_hash;

        // Update chain-committed state version from the synced block's header.
        // (Same reasoning as in commit_block_and_buffered)
        self.last_chain_committed_state_version = block.header.state_version;

        // Reset backoff tracking - new height means fresh round counting
        self.view_at_height_start = self.view;

        // Update latest QC (this may help us catch up further)
        if self
            .latest_qc
            .as_ref()
            .is_none_or(|existing| qc.height.0 > existing.height.0)
        {
            self.latest_qc = Some(qc.clone());
            // HotStuff-2 unlock for synced QC
            self.maybe_unlock_for_qc(&qc);
        }

        // Also cache the parent_qc from the block header if it's newer
        if !block.header.parent_qc.is_genesis()
            && self
                .latest_qc
                .as_ref()
                .is_none_or(|existing| block.header.parent_qc.height.0 > existing.height.0)
        {
            self.latest_qc = Some(block.header.parent_qc.clone());
            // HotStuff-2 unlock for parent QC
            self.maybe_unlock_for_qc(&block.header.parent_qc);
        }

        // Clean up old state
        let removed_blocks = self.cleanup_old_state(height);

        // Emit actions for the synced block
        let mut actions = vec![
            Action::PersistBlock {
                block: block.clone(),
                qc: qc.clone(),
            },
            Action::EmitCommittedBlock {
                block: block.clone(),
                qc,
            },
            Action::Continuation(ProtocolEvent::BlockCommitted {
                block_hash,
                height,
                block: block.clone(),
            }),
        ];

        // Cancel any pending fetches for removed blocks
        for block_hash in removed_blocks {
            actions.push(Action::CancelFetch { block_hash });
        }

        // After syncing a block, check if we have buffered commits for subsequent heights
        // that can now be processed. This handles the case where:
        // 1. Block N was incomplete, blocking commits
        // 2. Blocks N+1, N+2, ... were complete but buffered in pending_commits
        // 3. Sync provided block N
        // 4. Now we can drain the pending_commits buffer
        actions.extend(self.drain_pending_commits());

        actions
    }

    /// Drain buffered out-of-order commits that are now ready to be processed.
    ///
    /// Called after committing a block (via sync or normal consensus) to check
    /// if there are buffered commits at subsequent heights that can now proceed.
    fn drain_pending_commits(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();

        loop {
            let next_height = self.committed_height + 1;

            // Check if we have a buffered commit for the next height
            let Some((block_hash, qc)) = self.pending_commits.remove(&next_height) else {
                break;
            };

            debug!(
                validator = ?self.validator_id(),
                height = next_height,
                block_hash = ?block_hash,
                "Processing buffered commit after sync"
            );

            // Try to commit this block - it should be complete since it was buffered
            // in pending_commits (not pending_commits_awaiting_data)
            let commit_actions = self.on_block_ready_to_commit(block_hash, qc);
            actions.extend(commit_actions);

            // If on_block_ready_to_commit didn't actually commit (e.g., block not found),
            // stop trying to drain further
            if self.committed_height < next_height {
                break;
            }
        }

        actions
    }

    /// Try to apply all consecutive verified synced blocks.
    ///
    /// Called after a synced block's QC is verified. Applies all verified blocks
    /// in height order starting from committed_height + 1, then drains any
    /// buffered out-of-order blocks that can now be submitted for verification.
    fn try_apply_verified_synced_blocks(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();

        // First, apply all consecutive verified blocks
        loop {
            let next_height = self.committed_height + 1;

            // Log state for debugging
            let verified_heights: Vec<_> = self
                .pending_synced_block_verifications
                .values()
                .filter(|p| p.verified)
                .map(|p| p.block.header.height.0)
                .collect();
            let unverified_heights: Vec<_> = self
                .pending_synced_block_verifications
                .values()
                .filter(|p| !p.verified)
                .map(|p| p.block.header.height.0)
                .collect();
            info!(
                committed_height = self.committed_height,
                next_height,
                verified_heights = ?verified_heights,
                unverified_heights = ?unverified_heights,
                "try_apply_verified_synced_blocks: checking"
            );

            // Find a verified block at the next height
            let block_hash = self
                .pending_synced_block_verifications
                .iter()
                .find(|(_, p)| p.verified && p.block.header.height.0 == next_height)
                .map(|(h, _)| *h);

            let Some(hash) = block_hash else {
                // No verified block at next height - stop applying
                info!(next_height, "No verified block at next height - stopping");
                break;
            };

            // Remove and apply the block
            let pending = self
                .pending_synced_block_verifications
                .remove(&hash)
                .unwrap();
            actions.extend(self.apply_synced_block(pending.block, pending.qc));
        }

        // After applying blocks, drain more buffered blocks for parallel verification
        actions.extend(self.try_drain_buffered_synced_blocks());

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // View Change
    // ═══════════════════════════════════════════════════════════════════════════
    // Implicit Round Advancement (HotStuff-2 Style)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Advance the round locally (implicit view change).
    ///
    /// This is called when a timeout occurs and we need to try a new round.
    /// Unlike explicit view changes, this doesn't require coordinated voting -
    /// each validator advances locally.
    ///
    /// Returns actions to propose if we're the new proposer.
    #[instrument(skip(self), fields(new_round = self.view + 1))]
    fn advance_round(&mut self) -> Vec<Action> {
        // The next height to propose is one above the highest certified block,
        // NOT one above the committed block. This matches on_proposal_timer behavior.
        let height = self
            .latest_qc
            .as_ref()
            .map(|qc| qc.height.0 + 1)
            .unwrap_or(self.committed_height + 1);
        let old_round = self.view;
        self.view += 1;
        self.view_changes += 1;

        info!(
            validator = ?self.validator_id(),
            height = height,
            old_round = old_round,
            new_round = self.view,
            view_changes = self.view_changes,
            "Advancing round locally (implicit view change)"
        );

        // Timeout-based unlock: If no QC has formed at this height, we clear our
        // vote lock to allow voting for a new proposal in the next round. Safety is
        // maintained by quorum intersection — even if a QC did form but we haven't
        // seen it, a conflicting block can never reach quorum.
        // Note: this is more aggressive than HotStuff-2 (which requires a TC or
        // higher QC to unlock). See `maybe_unlock_for_qc` for QC-based unlocking.
        let latest_qc_height = self.latest_qc.as_ref().map(|qc| qc.height.0).unwrap_or(0);
        if latest_qc_height < height {
            // No QC formed at current height - safe to unlock
            let had_vote = self.voted_heights.remove(&height).is_some();
            let cleared_votes = self.clear_vote_tracking_for_height(height, self.view);

            if had_vote || cleared_votes > 0 {
                info!(
                    validator = ?self.validator_id(),
                    height = height,
                    new_round = self.view,
                    latest_qc_height = latest_qc_height,
                    cleared_votes = cleared_votes,
                    "Unlocking vote at height (no QC formed, safe by quorum intersection)"
                );
            }
        }

        // Check if we're the new proposer for this height/round
        if self.should_propose(height, self.view) {
            // Check if we've already voted at this height - if so, we're locked
            if let Some(&(existing_hash, _)) = self.voted_heights.get(&height) {
                info!(
                    validator = ?self.validator_id(),
                    height = height,
                    new_round = self.view,
                    existing_block = ?existing_hash,
                    "Vote-locked at this height, re-proposing"
                );
                return self.repropose_locked_block(existing_hash, height);
            }

            info!(
                validator = ?self.validator_id(),
                height = height,
                new_round = self.view,
                "We are the new proposer after round advance - building block"
            );

            // Build and broadcast a new block (use fallback block builder)
            return self.build_and_broadcast_fallback_block(height, self.view);
        }

        // Not the proposer - just reschedule the timer
        vec![Action::SetTimer {
            id: TimerId::Proposal,
            duration: self.config.proposal_interval,
        }]
    }

    /// Called when we receive a QC from a block header that allows us to unlock.
    ///
    /// # HotStuff-2 Unlock Rule
    ///
    /// When we see a QC at height H, we can safely remove vote locks at heights ≤ H:
    ///
    /// - **Heights < H**: These are older heights where consensus has clearly moved past.
    ///   Any block we voted for at these heights either got committed or was abandoned.
    ///
    /// - **Height = H (same height as QC)**: If we voted for a different block B' at height H
    ///   but the QC is for block B, then B' can never get a QC (since 2f+1 already voted for B,
    ///   leaving at most f honest validators who could vote for B'). Our lock is now irrelevant.
    ///   If we voted for the same block B, unlocking is trivially safe.
    ///
    /// This enables voting for new blocks at height H+1 that extend the newly certified block,
    /// even if we previously voted for a different block at H+1 that didn't get a QC.
    ///
    /// # Safety Argument
    ///
    /// The key invariant is: once a QC exists for block B at height H, no conflicting block
    /// at height H can ever get a QC (quorum intersection). Therefore, unlocking vote locks
    /// at height H is safe - any conflicting vote would be "dead" anyway.
    ///
    /// # View Synchronization
    ///
    /// This method also synchronizes our view/round to match the QC. In HotStuff-2,
    /// liveness requires that nodes eventually reach the same view. When we see a QC
    /// formed at round R, we know the network has made progress, so we advance our
    /// view to at least R (ready to participate in round R or later).
    ///
    /// This is the key mechanism that prevents view divergence: nodes that fall behind
    /// (e.g., due to network partitions or slow clocks) will catch up when they see
    /// QCs from the rest of the network.
    fn maybe_unlock_for_qc(&mut self, qc: &QuorumCertificate) {
        if qc.is_genesis() {
            return;
        }

        // View synchronization: advance our view to match the QC's round.
        // This ensures liveness by keeping nodes in sync with network progress.
        //
        // We sync to qc.round (not qc.round + 1) because:
        // - The QC proves consensus succeeded at this round
        // - We should be ready to participate in this round or later
        // - The proposer for the next height will use their current view
        if qc.round > self.view {
            info!(
                validator = ?self.validator_id(),
                old_view = self.view,
                new_view = qc.round,
                qc_height = qc.height.0,
                "View synchronization: advancing view to match QC"
            );
            self.view = qc.round;
        }

        // Remove vote locks for heights at or below the QC height.
        // This is safe because:
        // 1. Heights < H: consensus has moved past these heights
        // 2. Height = H: if we voted for a different block, it can never get a QC (quorum intersection)
        let qc_height = qc.height.0;
        let unlocked: Vec<u64> = self
            .voted_heights
            .keys()
            .filter(|h| **h <= qc_height)
            .copied()
            .collect();

        for height in unlocked {
            if self.voted_heights.remove(&height).is_some() {
                trace!(
                    validator = ?self.validator_id(),
                    height = height,
                    qc_height = qc_height,
                    "Unlocked vote due to higher QC"
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Transaction Fetch Protocol
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle transactions received from a fetch request.
    ///
    /// Adds the fetched transactions to the pending block and triggers
    /// voting if the block is now complete.
    #[instrument(skip(self, transactions), fields(block_hash = ?block_hash, tx_count = transactions.len()))]
    pub fn on_transaction_fetch_received(
        &mut self,
        block_hash: Hash,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Vec<Action> {
        let validator_id = self.validator_id();

        // First phase: add transactions and check state
        let (added, still_missing, is_complete, needs_construct) = {
            let Some(pending) = self.pending_blocks.get_mut(&block_hash) else {
                debug!(
                    block_hash = ?block_hash,
                    "Received fetched transactions for unknown/completed block"
                );
                return vec![];
            };

            let mut added = 0;
            for tx in transactions {
                if pending.add_transaction_arc(tx) {
                    added += 1;
                }
            }

            let still_missing = pending.missing_transaction_count();
            let is_complete = pending.is_complete();
            let needs_construct = is_complete && pending.block().is_none();

            (added, still_missing, is_complete, needs_construct)
        };

        debug!(
            validator = ?validator_id,
            block_hash = ?block_hash,
            added = added,
            still_missing = still_missing,
            "Added fetched transactions to pending block"
        );

        // Check if block is now complete
        if !is_complete {
            // Still missing data - request remaining items
            // The runner handles retries, so we just re-emit the request
            let Some(pending) = self.pending_blocks.get(&block_hash) else {
                return vec![];
            };

            let mut actions = Vec::new();
            let proposer = pending.header().proposer;

            // Request still-missing transactions
            let missing_txs = pending.missing_transactions();
            if !missing_txs.is_empty() {
                debug!(
                    validator = ?validator_id,
                    block_hash = ?block_hash,
                    still_missing = missing_txs.len(),
                    "Re-requesting remaining missing transactions"
                );
                actions.push(Action::FetchTransactions {
                    block_hash,
                    proposer,
                    tx_hashes: missing_txs,
                });
            }

            // Request still-missing certificates
            let missing_certs = pending.missing_certificates();
            if !missing_certs.is_empty() {
                debug!(
                    validator = ?validator_id,
                    block_hash = ?block_hash,
                    still_missing = missing_certs.len(),
                    "Re-requesting remaining missing certificates"
                );
                actions.push(Action::FetchCertificates {
                    block_hash,
                    proposer,
                    cert_hashes: missing_certs,
                });
            }

            return actions;
        }

        // Second phase: construct block if needed
        if needs_construct {
            if let Some(pending) = self.pending_blocks.get_mut(&block_hash) {
                if let Err(e) = pending.construct_block() {
                    warn!("Failed to construct block after tx fetch: {}", e);
                    return vec![];
                }
            }
        }

        info!(
            validator = ?validator_id,
            block_hash = ?block_hash,
            "Pending block completed after transaction fetch"
        );

        // Trigger QC verification (for non-genesis) or vote directly (for genesis)
        let mut actions = self.trigger_qc_verification_or_vote(block_hash);

        // Check if this block had a pending commit waiting for data
        actions.extend(self.try_commit_pending_data(block_hash));

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Certificate Fetch Protocol
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle certificates received from a fetch request.
    ///
    /// Adds the fetched certificates to the pending block and triggers
    /// voting if the block is now complete.
    ///
    /// Note: Certificates should be verified by the caller before passing here.
    /// This method assumes the certificates have been validated.
    #[instrument(skip(self, certificates), fields(block_hash = ?block_hash, cert_count = certificates.len()))]
    pub fn on_certificate_fetch_received(
        &mut self,
        block_hash: Hash,
        certificates: Vec<Arc<TransactionCertificate>>,
    ) -> Vec<Action> {
        let validator_id = self.validator_id();

        // First phase: add certificates and check state
        let (added, still_missing, is_complete, needs_construct) = {
            let Some(pending) = self.pending_blocks.get_mut(&block_hash) else {
                debug!(
                    block_hash = ?block_hash,
                    "Received fetched certificates for unknown/completed block"
                );
                return vec![];
            };

            let mut added = 0;
            for cert in certificates {
                if pending.add_certificate(cert) {
                    added += 1;
                }
            }

            let still_missing = pending.missing_certificate_count();
            let is_complete = pending.is_complete();
            let needs_construct = is_complete && pending.block().is_none();

            (added, still_missing, is_complete, needs_construct)
        };

        debug!(
            validator = ?validator_id,
            block_hash = ?block_hash,
            added = added,
            still_missing = still_missing,
            "Added fetched certificates to pending block"
        );

        // Check if block is now complete
        if !is_complete {
            // Still missing data - request remaining items
            // The runner handles retries, so we just re-emit the request
            let Some(pending) = self.pending_blocks.get(&block_hash) else {
                return vec![];
            };

            let mut actions = Vec::new();
            let proposer = pending.header().proposer;

            // Request still-missing transactions
            let missing_txs = pending.missing_transactions();
            if !missing_txs.is_empty() {
                debug!(
                    validator = ?validator_id,
                    block_hash = ?block_hash,
                    still_missing = missing_txs.len(),
                    "Re-requesting remaining missing transactions"
                );
                actions.push(Action::FetchTransactions {
                    block_hash,
                    proposer,
                    tx_hashes: missing_txs,
                });
            }

            // Request still-missing certificates
            let missing_certs = pending.missing_certificates();
            if !missing_certs.is_empty() {
                debug!(
                    validator = ?validator_id,
                    block_hash = ?block_hash,
                    still_missing = missing_certs.len(),
                    "Re-requesting remaining missing certificates"
                );
                actions.push(Action::FetchCertificates {
                    block_hash,
                    proposer,
                    cert_hashes: missing_certs,
                });
            }

            return actions;
        }

        // Second phase: construct block if needed
        if needs_construct {
            if let Some(pending) = self.pending_blocks.get_mut(&block_hash) {
                if let Err(e) = pending.construct_block() {
                    warn!("Failed to construct block after cert fetch: {}", e);
                    return vec![];
                }
            }
        }

        info!(
            validator = ?validator_id,
            block_hash = ?block_hash,
            "Pending block completed after certificate fetch"
        );

        // Trigger QC verification (for non-genesis) or vote directly (for genesis)
        let mut actions = self.trigger_qc_verification_or_vote(block_hash);

        // Check if this block had a pending commit waiting for data
        actions.extend(self.try_commit_pending_data(block_hash));

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Transaction Monitoring
    // ═══════════════════════════════════════════════════════════════════════════

    /// Check if any pending blocks are now complete after a transaction arrived.
    ///
    /// When a transaction arrives via gossip, it might complete a pending block
    /// that was waiting for that transaction. This method checks all pending
    /// blocks and triggers voting if any are now complete.
    pub fn check_pending_blocks_for_transaction(
        &mut self,
        tx_hash: Hash,
        mempool: &HashMap<Hash, Arc<RoutableTransaction>>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Find pending blocks that need this transaction
        let block_hashes: Vec<Hash> = self
            .pending_blocks
            .iter()
            .filter(|(_, pending)| pending.needs_transaction(&tx_hash))
            .map(|(hash, _)| *hash)
            .collect();

        for block_hash in block_hashes {
            if let Some(pending) = self.pending_blocks.get_mut(&block_hash) {
                if let Some(tx) = mempool.get(&tx_hash) {
                    pending.add_transaction_arc(Arc::clone(tx));
                }

                // Check if block is now complete
                if pending.is_complete() {
                    // Construct block if needed
                    if pending.block().is_none() {
                        if let Err(e) = pending.construct_block() {
                            warn!("Failed to construct block after tx arrival: {}", e);
                            continue;
                        }
                    }

                    debug!(
                        validator = ?self.validator_id(),
                        block_hash = ?block_hash,
                        tx_hash = ?tx_hash,
                        "Pending block completed after transaction arrived"
                    );

                    // Trigger QC verification (for non-genesis) or vote directly (for genesis)
                    // This is CRITICAL: we must verify QC signatures before voting, even when
                    // transactions arrive late. Previously this called try_vote_on_block directly,
                    // which skipped QC verification - a safety bug.
                    actions.extend(self.trigger_qc_verification_or_vote(block_hash));

                    // Check if this block had a pending commit waiting for data
                    actions.extend(self.try_commit_pending_data(block_hash));
                }
            }
        }

        actions
    }

    /// Check if any pending blocks are now complete after a certificate was finalized.
    ///
    /// When a TransactionCertificate is finalized locally, it might complete a pending block
    /// that was waiting for that certificate. This method checks all pending blocks and
    /// triggers voting if any are now complete.
    pub fn check_pending_blocks_for_certificate(
        &mut self,
        cert_hash: Hash,
        certificates: &HashMap<Hash, Arc<TransactionCertificate>>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Find pending blocks that need this certificate
        let block_hashes: Vec<Hash> = self
            .pending_blocks
            .iter()
            .filter(|(_, pending)| pending.missing_certificates().contains(&cert_hash))
            .map(|(hash, _)| *hash)
            .collect();

        for block_hash in block_hashes {
            if let Some(pending) = self.pending_blocks.get_mut(&block_hash) {
                // Try to add the certificate
                if let Some(cert) = certificates.get(&cert_hash) {
                    pending.add_certificate(Arc::clone(cert));
                }

                // Check if block is now complete
                if pending.is_complete() {
                    // Construct block if needed
                    if pending.block().is_none() {
                        if let Err(e) = pending.construct_block() {
                            warn!("Failed to construct block after cert arrival: {}", e);
                            continue;
                        }
                    }

                    debug!(
                        validator = ?self.validator_id(),
                        block_hash = ?block_hash,
                        cert_hash = ?cert_hash,
                        "Pending block completed after certificate finalized"
                    );

                    // Trigger QC verification (for non-genesis) or vote directly (for genesis)
                    // This is CRITICAL: we must verify QC signatures before voting, even when
                    // certificates arrive late. Previously this called try_vote_on_block directly,
                    // which skipped QC verification - a safety bug.
                    actions.extend(self.trigger_qc_verification_or_vote(block_hash));

                    // Check if this block had a pending commit waiting for data
                    actions.extend(self.try_commit_pending_data(block_hash));
                }
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Cleanup
    // ═══════════════════════════════════════════════════════════════════════════

    /// Clear vote tracking for a specific height (used during HotStuff-2 unlock).
    ///
    /// This removes all recorded votes for the given height, allowing validators
    /// to vote again after a view change proves no QC formed. This is safe because
    /// the view change certificate provides proof that consensus has moved on.
    ///
    /// The `new_round` parameter is used to selectively clear pending vote verifications:
    /// only verifications for votes at rounds LESS than the new round are cleared.
    /// This prevents a race condition where:
    /// 1. We receive a vote from another validator at round N
    /// 2. Before verification completes, we advance to round N
    /// 3. If we cleared ALL verifications, we'd lose the valid vote at round N
    ///
    /// Returns the number of vote entries cleared.
    fn clear_vote_tracking_for_height(&mut self, height: u64, new_round: u64) -> usize {
        let mut cleared = 0;

        // Clear received_votes_by_height for this height
        // This allows us to accept new votes from validators who previously voted
        self.received_votes_by_height.retain(|(h, _), _| {
            if *h == height {
                cleared += 1;
                false
            } else {
                true
            }
        });

        // Clear vote sets for blocks at this height, but ONLY for rounds less than
        // the new round. Vote sets at the current or higher rounds may contain valid
        // votes that can still form a QC.
        //
        // Note: vote_sets are keyed by block_hash, so we need to check the height and round.
        // If another validator's fallback block at round N has already accumulated votes
        // in our vote_sets before we advance to round N, we should preserve those votes.
        self.vote_sets.retain(|_hash, vote_set| {
            // Keep if: different height OR round >= new_round OR round unknown
            vote_set.height().is_none_or(|h| h != height)
                || vote_set.round().is_none_or(|r| r >= new_round)
        });

        cleared
    }

    /// Clean up old state after commit.
    ///
    /// Returns the hashes of pending blocks that were removed, so callers can
    /// emit `CancelFetch` actions to clean up any in-flight fetch operations.
    fn cleanup_old_state(&mut self, committed_height: u64) -> Vec<Hash> {
        // Collect hashes of pending blocks that will be removed
        let removed_hashes: Vec<Hash> = self
            .pending_blocks
            .iter()
            .filter(|(_, pending)| pending.header().height.0 <= committed_height)
            .map(|(hash, _)| *hash)
            .collect();

        // Remove pending blocks at or below committed height
        self.pending_blocks
            .retain(|_, pending| pending.header().height.0 > committed_height);

        // Also clean up pending_block_created_at to match pending_blocks
        self.pending_block_created_at
            .retain(|hash, _| self.pending_blocks.contains_key(hash));

        // Remove vote sets at or below committed height
        self.vote_sets
            .retain(|_hash, vote_set| vote_set.height().is_none_or(|h| h > committed_height));

        // Remove old voted_heights entries
        self.voted_heights
            .retain(|height, _| *height > committed_height);

        // Remove old received_votes_by_height entries
        self.received_votes_by_height
            .retain(|(height, _), _| *height > committed_height);

        // Remove certified blocks at or below committed height
        self.certified_blocks
            .retain(|_, (block, _)| block.header.height.0 > committed_height);

        // Remove pending commits awaiting data at or below committed height
        self.pending_commits_awaiting_data
            .retain(|_, (height, _)| *height > committed_height);

        // Remove buffered synced blocks at or below committed height
        self.buffered_synced_blocks
            .retain(|height, _| *height > committed_height);

        // Remove pending synced block verifications at or below committed height.
        // These are synced blocks awaiting QC verification that are now stale because
        // consensus has already committed past their height.
        self.pending_synced_block_verifications
            .retain(|_, pending| pending.block.header.height.0 > committed_height);

        // Remove pending QC verifications for blocks at or below committed height.
        // We look up the block hash in pending_blocks to get the height - if the block
        // is no longer in pending_blocks (was just cleaned up above), we remove the
        // pending verification since we won't need it.
        self.pending_qc_verifications
            .retain(|hash, _| self.pending_blocks.contains_key(hash));

        // Remove pending CycleProof verifications for blocks no longer in pending_blocks.
        self.pending_cycle_proof_verifications
            .retain(|hash, _| self.pending_blocks.contains_key(hash));

        // Remove verified CycleProofs for blocks no longer in pending_blocks.
        self.verified_cycle_proofs
            .retain(|hash| self.pending_blocks.contains_key(hash));

        // Remove pending state root verifications for blocks no longer in pending_blocks.
        self.pending_state_root_verifications
            .retain(|hash, _| self.pending_blocks.contains_key(hash));

        // Remove in-flight state root verifications for blocks no longer in pending_blocks.
        self.state_root_verifications_in_flight
            .retain(|hash| self.pending_blocks.contains_key(hash));

        // Remove verified state roots for blocks no longer in pending_blocks.
        self.verified_state_roots
            .retain(|hash| self.pending_blocks.contains_key(hash));

        // Remove in-flight transaction root verifications for blocks no longer in pending_blocks.
        self.transaction_root_verifications_in_flight
            .retain(|hash| self.pending_blocks.contains_key(hash));

        // Remove verified transaction roots for blocks no longer in pending_blocks.
        self.verified_transaction_roots
            .retain(|hash| self.pending_blocks.contains_key(hash));

        // Remove verified QC cache entries for heights at or below committed height.
        // We keep entries slightly above committed_height in case of view changes
        // where multiple proposals at the same height share the same parent_qc.
        self.verified_qcs
            .retain(|_, height| *height > committed_height.saturating_sub(2));

        removed_hashes
    }

    /// Check pending blocks and emit fetch requests for those that have been
    /// waiting longer than the configured timeout.
    ///
    /// This is called periodically by the cleanup timer. Instead of fetching
    /// immediately when a block header arrives, we give gossip and local
    /// certificate creation time to fill in the missing data first.
    ///
    /// - `transaction_fetch_timeout`: How long to wait before fetching missing txs
    /// - `certificate_fetch_timeout`: How long to wait before fetching missing certs
    pub fn check_pending_block_fetches(&self) -> Vec<Action> {
        // Don't fetch for gossip blocks while syncing.
        // Sync delivers complete blocks that will supersede these pending blocks.
        // This prevents FetchManager from consuming all request slots and starving sync.
        if self.syncing {
            return vec![];
        }

        let now = self.now;
        let tx_timeout = self.config.transaction_fetch_timeout;
        let cert_timeout = self.config.certificate_fetch_timeout;
        let mut actions = Vec::new();

        for (block_hash, pending) in &self.pending_blocks {
            // Skip complete blocks
            if pending.is_complete() {
                continue;
            }

            let Some(&created_at) = self.pending_block_created_at.get(block_hash) else {
                continue;
            };

            let age = now.saturating_sub(created_at);
            let proposer = pending.header().proposer;

            // Check if we should fetch missing transactions
            let missing_txs = pending.missing_transactions();
            if !missing_txs.is_empty() && age >= tx_timeout {
                debug!(
                    validator = ?self.validator_id(),
                    block_hash = ?block_hash,
                    missing_tx_count = missing_txs.len(),
                    age_ms = age.as_millis(),
                    timeout_ms = tx_timeout.as_millis(),
                    "Fetch timeout reached, requesting missing transactions"
                );
                actions.push(Action::FetchTransactions {
                    block_hash: *block_hash,
                    proposer,
                    tx_hashes: missing_txs,
                });
            }

            // Check if we should fetch missing certificates
            let missing_certs = pending.missing_certificates();
            if !missing_certs.is_empty() && age >= cert_timeout {
                debug!(
                    validator = ?self.validator_id(),
                    block_hash = ?block_hash,
                    missing_cert_count = missing_certs.len(),
                    age_ms = age.as_millis(),
                    timeout_ms = cert_timeout.as_millis(),
                    "Fetch timeout reached, requesting missing certificates"
                );
                actions.push(Action::FetchCertificates {
                    block_hash: *block_hash,
                    proposer,
                    cert_hashes: missing_certs,
                });
            }
        }

        actions
    }

    /// Check if we're behind and need to catch up via sync.
    ///
    /// This is called periodically by the cleanup timer to detect when:
    /// 1. We have a latest_qc at a height higher than committed_height
    /// 2. We can't make progress because the next block to commit is missing or incomplete
    ///
    /// If we detect we're stuck, we trigger sync to the latest_qc height.
    /// This handles edge cases where:
    /// - Block headers are dropped
    /// - Transaction/certificate fetches fail permanently
    /// - A block in the middle of the chain is incomplete while later blocks are ready
    pub fn check_sync_health(&mut self) -> Vec<Action> {
        let Some(latest_qc) = &self.latest_qc else {
            return vec![];
        };

        let qc_height = latest_qc.height.0;
        let qc_hash = latest_qc.block_hash;

        // If we're already at or past the QC height, nothing to do
        if self.committed_height >= qc_height {
            return vec![];
        }

        // If we're already syncing, don't trigger another sync
        if self.syncing {
            return vec![];
        }

        // Check if we can make progress from our current position.
        // The critical check is whether we have a COMPLETE block at the next height
        // we need to commit. Having blocks at higher heights doesn't help if we're
        // stuck on an earlier incomplete block.
        let next_needed_height = self.committed_height + 1;

        // Check if we have the block data AND the commit authority for the next height.
        // Having block data alone is NOT enough - we also need a pending commit
        // (which comes from a QC that references this block as its parent).
        let has_next_block = self.has_complete_block_at_height(next_needed_height);
        let has_pending_commit = self.pending_commits.contains_key(&next_needed_height);

        // Log sync health status when behind
        let gap = qc_height.saturating_sub(self.committed_height);
        if gap > 5 {
            let pending_commit_count = self.pending_commits.len();
            let pending_data_count = self.pending_commits_awaiting_data.len();
            debug!(
                validator = ?self.validator_id(),
                committed_height = self.committed_height,
                next_needed_height = next_needed_height,
                qc_height = qc_height,
                gap = gap,
                has_next_complete = has_next_block,
                has_pending_commit = has_pending_commit,
                pending_commits = pending_commit_count,
                pending_commits_awaiting_data = pending_data_count,
                certified_blocks = self.certified_blocks.len(),
                pending_blocks = self.pending_blocks.len(),
                "Sync health check status"
            );
        }

        if has_next_block {
            if has_pending_commit {
                // We have block data AND commit authority - should proceed normally.
                // But if we're significantly behind, something is wrong with the commit flow.
                // This can happen after sync when the node's view of the chain diverges from
                // what it was voting on - the blocks in certified_blocks may have different
                // hashes than what the QCs reference.
                if gap > 10 {
                    warn!(
                        validator = ?self.validator_id(),
                        committed_height = self.committed_height,
                        next_needed_height = next_needed_height,
                        qc_height = qc_height,
                        gap = gap,
                        "Have complete block and pending commit but significantly behind - triggering sync to recover"
                    );
                    return self.start_sync(qc_height, qc_hash);
                }
                return vec![];
            }

            // We have block data but NO pending commit.
            // This is normal during the window between block completion and QC formation.
            // However, if the gap is significant (> 3), it suggests the QC that would
            // trigger the commit was lost due to packet loss.
            //
            // The QC for block N+1 triggers commit of block N, so if we never formed/received
            // QC N+1, we have no way to commit block N. Trigger sync to recover.
            if gap > 3 {
                warn!(
                    validator = ?self.validator_id(),
                    committed_height = self.committed_height,
                    next_needed_height = next_needed_height,
                    qc_height = qc_height,
                    gap = gap,
                    "Have complete block but no pending commit (missing QC) - triggering sync to recover"
                );
                return self.start_sync(qc_height, qc_hash);
            }
            // Gap is small, give normal consensus time to catch up
            return vec![];
        }

        // We're behind and can't make progress - the next block we need is either
        // missing entirely or incomplete (waiting for transactions/certificates).
        // Trigger sync to get the complete block data.
        info!(
            validator = ?self.validator_id(),
            committed_height = self.committed_height,
            next_needed_height = next_needed_height,
            qc_height = qc_height,
            "Sync health check: can't make progress, triggering catch-up sync"
        );

        self.start_sync(qc_height, qc_hash)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Accessors
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get the current committed height.
    pub fn committed_height(&self) -> u64 {
        self.committed_height
    }

    /// Get the committed block hash.
    pub fn committed_hash(&self) -> Hash {
        self.committed_hash
    }

    /// Get the latest QC.
    pub fn latest_qc(&self) -> Option<&QuorumCertificate> {
        self.latest_qc.as_ref()
    }

    /// Get the current view/round.
    pub fn view(&self) -> u64 {
        self.view
    }

    /// Get BFT statistics for monitoring.
    pub fn stats(&self) -> BftStats {
        BftStats {
            view_changes: self.view_changes,
            current_round: self.view,
            committed_height: self.committed_height,
        }
    }

    /// Check if we are the proposer for the current height and round.
    pub fn is_current_proposer(&self) -> bool {
        let next_height = self
            .latest_qc
            .as_ref()
            .map(|qc| qc.height.0 + 1)
            .unwrap_or(self.committed_height + 1);
        self.should_propose(next_height, self.view)
    }

    /// Get the BFT configuration.
    pub fn config(&self) -> &BftConfig {
        &self.config
    }

    /// Get the voted heights map (for testing/debugging).
    pub fn voted_heights(&self) -> &HashMap<u64, (Hash, u64)> {
        &self.voted_heights
    }

    /// Check if we have a COMPLETE block at the given height that can be committed.
    ///
    /// This only returns true if the block is fully
    /// constructed and ready for commit. Incomplete pending blocks (waiting for
    /// transactions/certificates) return false.
    ///
    /// Returns true if:
    /// - Height is already committed
    /// - Block is in `pending_blocks` AND is complete (has all data, block constructed)
    /// - Block is in `certified_blocks` (always complete)
    /// - Block is in `pending_synced_block_verifications` (synced blocks are always complete)
    /// - Block is in `buffered_synced_blocks` (synced blocks are always complete)
    fn has_complete_block_at_height(&self, height: u64) -> bool {
        // Already committed
        if height <= self.committed_height {
            return true;
        }

        // In pending blocks - but only if complete and constructed
        if self
            .pending_blocks
            .values()
            .any(|pb| pb.header().height.0 == height && pb.is_complete() && pb.block().is_some())
        {
            return true;
        }

        // In certified blocks (always complete)
        if self
            .certified_blocks
            .values()
            .any(|(block, _)| block.header.height.0 == height)
        {
            return true;
        }

        // In pending synced block verifications (synced blocks are always complete)
        if self
            .pending_synced_block_verifications
            .values()
            .any(|p| p.block.header.height.0 == height)
        {
            return true;
        }

        // In buffered synced blocks (synced blocks are always complete)
        if self.buffered_synced_blocks.contains_key(&height) {
            return true;
        }

        false
    }

    /// Check if this node will propose at the next height.
    ///
    /// Returns true if:
    /// 1. We are the proposer for the next height/round
    /// 2. We haven't already voted at that height
    ///
    /// This is used to avoid destructively taking certificates from execution
    /// state when we won't actually be proposing a block.
    pub fn will_propose_next(&self) -> bool {
        let next_height = self
            .latest_qc
            .as_ref()
            .map(|qc| qc.height.0 + 1)
            .unwrap_or(self.committed_height + 1);
        let round = self.view;

        self.should_propose(next_height, round) && !self.voted_heights.contains_key(&next_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        batch_verify_bls_same_message, generate_bls_keypair, verify_bls12381_v1,
        zero_bls_signature, Bls12381G2Signature, SignerBitfield, StaticTopology, ValidatorInfo,
        ValidatorSet,
    };

    fn make_test_state() -> BftState {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();

        // Create validator set with ValidatorInfo
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        // Create topology
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));

        // Clone key bytes to create a new keypair since Bls12381G1PrivateKey doesn't impl Clone
        let key_bytes = keys[0].to_bytes();
        let signing_key = Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes");

        BftState::new(
            0,
            signing_key,
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        )
    }

    #[test]
    fn test_proposer_rotation() {
        let state = make_test_state();

        // Height 0, round 0 -> validator 0
        assert_eq!(state.proposer_for(0, 0), ValidatorId(0));
        // Height 1, round 0 -> validator 1
        assert_eq!(state.proposer_for(1, 0), ValidatorId(1));
        // Height 2, round 0 -> validator 2
        assert_eq!(state.proposer_for(2, 0), ValidatorId(2));
        // Height 0, round 1 -> validator 1
        assert_eq!(state.proposer_for(0, 1), ValidatorId(1));
    }

    #[test]
    fn test_should_propose() {
        let state = make_test_state();

        // Validator 0 should propose at height 0, round 0
        assert!(state.should_propose(0, 0));
        // But not at height 1
        assert!(!state.should_propose(1, 0));
        // Or height 0, round 1
        assert!(!state.should_propose(0, 1));
    }

    fn make_header_at_height(height: u64, timestamp: u64) -> BlockHeader {
        BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(height % 4), // Round-robin
            timestamp,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        }
    }

    #[test]
    fn test_timestamp_validation_skips_genesis() {
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        // Genesis block (height 0) should skip timestamp validation even with timestamp 0
        let header = BlockHeader {
            height: BlockHeight(0),
            parent_hash: Hash::from_bytes(b"genesis_parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 0, // Genesis timestamp is 0
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        // Should pass - genesis blocks skip timestamp validation
        assert!(state.validate_timestamp(&header).is_ok());
    }

    #[test]
    fn test_timestamp_validation_accepts_within_bounds() {
        let mut state = make_test_state();
        // Set clock to 100 seconds
        state.set_time(Duration::from_secs(100));

        // Timestamp at 99 seconds (1 second behind) - should be OK
        let header = make_header_at_height(1, 99_000);
        assert!(state.validate_timestamp(&header).is_ok());

        // Timestamp at 100 seconds (exactly now) - should be OK
        let header = make_header_at_height(1, 100_000);
        assert!(state.validate_timestamp(&header).is_ok());

        // Timestamp at 101 seconds (1 second ahead) - should be OK
        let header = make_header_at_height(1, 101_000);
        assert!(state.validate_timestamp(&header).is_ok());
    }

    #[test]
    fn test_timestamp_validation_rejects_too_old() {
        let mut state = make_test_state();
        // Set clock to 100 seconds
        state.set_time(Duration::from_secs(100));

        // Timestamp at 50 seconds (50 seconds behind, max delay is 30) - should fail
        let header = make_header_at_height(1, 50_000);
        let result = state.validate_timestamp(&header);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too old"));
    }

    #[test]
    fn test_timestamp_validation_rejects_too_far_ahead() {
        let mut state = make_test_state();
        // Set clock to 100 seconds
        state.set_time(Duration::from_secs(100));

        // Timestamp at 110 seconds (10 seconds ahead, max rush is 2) - should fail
        let header = make_header_at_height(1, 110_000);
        let result = state.validate_timestamp(&header);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too far ahead"));
    }

    #[test]
    fn test_timestamp_validation_at_boundary() {
        let mut state = make_test_state();
        // Set clock to 100 seconds
        state.set_time(Duration::from_secs(100));

        // At exactly max delay boundary (70 seconds = 100 - 30) - should be OK
        let header = make_header_at_height(1, 70_000);
        assert!(state.validate_timestamp(&header).is_ok());

        // Just past max delay (69.999 seconds) - should fail
        let header = make_header_at_height(1, 69_999);
        assert!(state.validate_timestamp(&header).is_err());

        // At exactly max rush boundary (102 seconds = 100 + 2) - should be OK
        let header = make_header_at_height(1, 102_000);
        assert!(state.validate_timestamp(&header).is_ok());

        // Just past max rush (102.001 seconds) - should fail
        let header = make_header_at_height(1, 102_001);
        assert!(state.validate_timestamp(&header).is_err());
    }

    #[test]
    fn test_timestamp_validation_skips_fallback_blocks() {
        let mut state = make_test_state();
        // Set clock to 100 seconds
        state.set_time(Duration::from_secs(100));

        // Fallback block with very old timestamp (50 seconds, which would normally fail)
        // This simulates a fallback block inheriting parent's weighted_timestamp after
        // multiple view changes spanning more than max_timestamp_delay_ms (30s)
        let header = BlockHeader {
            height: BlockHeight(1),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(1),
            timestamp: 50_000, // 50 seconds - would fail normal validation (now=100s, max_delay=30s)
            round: 5,          // High round indicates view changes occurred
            is_fallback: true,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        // Should pass - fallback blocks skip timestamp validation
        assert!(
            state.validate_timestamp(&header).is_ok(),
            "Fallback blocks should skip timestamp validation"
        );

        // Verify that a non-fallback block with the same timestamp would fail
        let normal_header = BlockHeader {
            height: BlockHeight(1),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(1),
            timestamp: 50_000,
            round: 5,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        assert!(
            state.validate_timestamp(&normal_header).is_err(),
            "Non-fallback blocks with old timestamps should fail validation"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // QC Signature Verification Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_qc_signature_verification_delegates_to_runner() {
        use hyperscale_core::Action;
        use hyperscale_types::SignerBitfield;

        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(1), 1, validator_set));
        let mut state = BftState::new(
            1,
            {
                let key_bytes = keys[1].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );

        // Set time for timestamp validation
        state.set_time(Duration::from_secs(100));

        // Set committed_height to 1 so we don't trigger sync for parent
        let parent_hash = Hash::from_bytes(b"parent_block");
        state.committed_height = 1;
        state.committed_hash = parent_hash;

        // Create a block at height 2 with a non-genesis parent QC
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);

        let parent_qc = QuorumCertificate {
            block_hash: parent_hash,
            height: BlockHeight(1),
            parent_block_hash: Hash::ZERO,
            round: 0,
            aggregated_signature: zero_bls_signature(), // Dummy for test
            signers,
            voting_power: VotePower(3),
            weighted_timestamp_ms: 99_000,
        };

        let header = BlockHeader {
            height: BlockHeight(2),
            parent_hash,
            parent_qc: parent_qc.clone(),
            proposer: ValidatorId(2), // height 2, round 0 -> validator 2
            timestamp: 100_000,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        // Process the block header
        let actions = state.on_block_header(
            header,
            vec![],          // retry_hashes
            vec![],          // priority_hashes
            vec![],          // tx_hashes
            vec![],          // cert_hashes
            vec![],          // deferred
            vec![],          // aborted
            HashMap::new(),  // commitment_proofs
            &HashMap::new(), // mempool
            &HashMap::new(), // certificates
        );

        // Should emit VerifyQcSignature action
        let has_verify_qc = actions
            .iter()
            .any(|a| matches!(a, Action::VerifyQcSignature { .. }));
        assert!(has_verify_qc, "Should delegate QC verification to runner");
    }

    #[test]
    fn test_qc_signature_verified_success_triggers_vote() {
        use hyperscale_core::Action;
        use hyperscale_types::SignerBitfield;

        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(1), 1, validator_set));
        let mut state = BftState::new(
            1,
            {
                let key_bytes = keys[1].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));

        // Set committed_height to 1 so we don't trigger sync for parent
        let parent_hash = Hash::from_bytes(b"parent_block");
        state.committed_height = 1;
        state.committed_hash = parent_hash;

        // Create block header with non-genesis QC
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);

        let parent_qc = QuorumCertificate {
            block_hash: parent_hash,
            height: BlockHeight(1),
            parent_block_hash: Hash::ZERO,
            round: 0,
            aggregated_signature: zero_bls_signature(),
            signers,
            voting_power: VotePower(3),
            weighted_timestamp_ms: 99_000,
        };

        let header = BlockHeader {
            height: BlockHeight(2),
            parent_hash,
            parent_qc: parent_qc.clone(),
            proposer: ValidatorId(2),
            timestamp: 100_000,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        let block_hash = header.hash();

        // First, process header to trigger QC verification
        let _ = state.on_block_header(
            header,
            vec![], // retry_hashes
            vec![], // priority_hashes
            vec![], // tx_hashes
            vec![], // cert_hashes
            vec![], // deferred
            vec![], // aborted
            HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );

        // Now simulate QC signature verified successfully
        let actions = state.on_qc_signature_verified(block_hash, true);

        // Should produce a vote (PersistAndBroadcastVote)
        let has_vote = actions
            .iter()
            .any(|a| matches!(a, Action::PersistAndBroadcastVote { .. }));
        assert!(has_vote, "Should broadcast vote after QC verified");
    }

    #[test]
    fn test_qc_signature_verified_failure_rejects_block() {
        use hyperscale_types::SignerBitfield;

        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(1), 1, validator_set));
        let mut state = BftState::new(
            1,
            {
                let key_bytes = keys[1].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));

        // Set committed_height to 1 so we don't trigger sync for parent
        let parent_hash = Hash::from_bytes(b"parent_block");
        state.committed_height = 1;
        state.committed_hash = parent_hash;

        // Create block header
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);

        let parent_qc = QuorumCertificate {
            block_hash: parent_hash,
            height: BlockHeight(1),
            parent_block_hash: Hash::ZERO,
            round: 0,
            aggregated_signature: zero_bls_signature(),
            signers,
            voting_power: VotePower(3),
            weighted_timestamp_ms: 99_000,
        };

        let header = BlockHeader {
            height: BlockHeight(2),
            parent_hash,
            parent_qc: parent_qc.clone(),
            proposer: ValidatorId(2),
            timestamp: 100_000,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        let block_hash = header.hash();

        // Process header to add pending verification
        let _ = state.on_block_header(
            header,
            vec![], // retry_hashes
            vec![], // priority_hashes
            vec![], // tx_hashes
            vec![], // cert_hashes
            vec![], // deferred
            vec![], // aborted
            HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );

        // Verify block is pending
        assert!(state.pending_blocks.contains_key(&block_hash));

        // Simulate QC signature verification FAILED
        let actions = state.on_qc_signature_verified(block_hash, false);

        // Should NOT produce any actions (no vote)
        assert!(
            actions.is_empty(),
            "Should not vote on block with invalid QC"
        );

        // Block should be removed from pending
        assert!(
            !state.pending_blocks.contains_key(&block_hash),
            "Block with invalid QC should be removed from pending"
        );
    }

    #[test]
    fn test_genesis_qc_skips_verification() {
        use hyperscale_core::Action;

        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(1), 1, validator_set));
        let mut state = BftState::new(
            1,
            {
                let key_bytes = keys[1].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));

        // Create block at height 1 with genesis QC (no signature to verify)
        let header = BlockHeader {
            height: BlockHeight(1),
            parent_hash: Hash::ZERO,
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(1), // height 1, round 0 -> validator 1
            timestamp: 100_000,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        // Process header
        let actions = state.on_block_header(
            header,
            vec![], // retry_hashes
            vec![], // priority_hashes
            vec![], // tx_hashes
            vec![], // cert_hashes
            vec![], // deferred
            vec![], // aborted
            HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );

        // Should NOT emit VerifyQcSignature (genesis QC)
        let has_verify_qc = actions
            .iter()
            .any(|a| matches!(a, Action::VerifyQcSignature { .. }));
        assert!(!has_verify_qc, "Genesis QC should skip verification");

        // Should directly vote (PersistAndBroadcastVote)
        let has_vote = actions
            .iter()
            .any(|a| matches!(a, Action::PersistAndBroadcastVote { .. }));
        assert!(has_vote, "Should vote directly for genesis QC block");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Implicit Round Advancement Tests (HotStuff-2 Style)
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_advance_round_increments_view() {
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        let initial_view = state.view;
        let _actions = state.advance_round();

        assert_eq!(state.view, initial_view + 1, "View should increment by 1");
    }

    #[test]
    fn test_advance_round_proposer_broadcasts() {
        use hyperscale_core::Action;

        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        // Validator 2 - will be proposer at (height=1, round=1) since (1+1)%4 = 2
        let topology = Arc::new(StaticTopology::new(ValidatorId(2), 1, validator_set));
        let mut state = BftState::new(
            2,
            {
                let key_bytes = keys[2].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));

        // Advance to round 1 - validator 2 becomes proposer
        let actions = state.advance_round();

        // Should broadcast a fallback block
        let has_broadcast = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastBlockHeader { .. }));
        assert!(
            has_broadcast,
            "Proposer should broadcast after round advance"
        );
    }

    #[test]
    fn test_advance_round_unlocks_when_no_qc() {
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        // Simulate having voted at height 1
        let block_hash = Hash::from_bytes(b"voted_block");
        state.voted_heights.insert(1, (block_hash, 0));

        // Advance round - should unlock since no QC at height 1
        let _actions = state.advance_round();

        assert!(
            !state.voted_heights.contains_key(&1),
            "Vote lock should be cleared when no QC at height"
        );
    }

    #[test]
    fn test_maybe_unlock_for_qc() {
        let mut state = make_test_state();

        // Set up vote locks at heights 1, 2, 3
        state
            .voted_heights
            .insert(1, (Hash::from_bytes(b"block1"), 0));
        state
            .voted_heights
            .insert(2, (Hash::from_bytes(b"block2"), 0));
        state
            .voted_heights
            .insert(3, (Hash::from_bytes(b"block3"), 0));

        // Receive QC at height 2 - should unlock heights 1 and 2
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"qc_block"),
            height: BlockHeight(2),
            parent_block_hash: Hash::from_bytes(b"parent"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        state.maybe_unlock_for_qc(&qc);

        assert!(
            !state.voted_heights.contains_key(&1),
            "Height 1 should be unlocked"
        );
        assert!(
            !state.voted_heights.contains_key(&2),
            "Height 2 should be unlocked"
        );
        assert!(
            state.voted_heights.contains_key(&3),
            "Height 3 should remain locked"
        );
    }

    #[test]
    fn test_view_sync_on_higher_qc() {
        let mut state = make_test_state();

        // Start at view 5
        state.view = 5;

        // Receive QC formed at round 10 - should advance view to 10
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"qc_block"),
            height: BlockHeight(2),
            parent_block_hash: Hash::from_bytes(b"parent"),
            round: 10,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        state.maybe_unlock_for_qc(&qc);

        assert_eq!(state.view, 10, "View should sync to QC's round");
    }

    #[test]
    fn test_view_sync_does_not_regress() {
        let mut state = make_test_state();

        // Start at view 15
        state.view = 15;

        // Receive QC formed at round 10 - should NOT regress view
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"qc_block"),
            height: BlockHeight(2),
            parent_block_hash: Hash::from_bytes(b"parent"),
            round: 10,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        state.maybe_unlock_for_qc(&qc);

        assert_eq!(state.view, 15, "View should NOT regress to lower QC round");
    }

    #[test]
    fn test_genesis_qc_does_not_sync_view() {
        let mut state = make_test_state();

        // Start at view 5
        state.view = 5;

        // Genesis QC should not affect view
        let genesis_qc = QuorumCertificate::genesis();
        state.maybe_unlock_for_qc(&genesis_qc);

        assert_eq!(state.view, 5, "Genesis QC should not change view");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Deferral and Abort Validation Tests
    // ═══════════════════════════════════════════════════════════════════════════

    /// Create a dummy CycleProof for testing structural validation.
    ///
    /// The proof is structurally valid but the signature is not cryptographically valid.
    /// This is sufficient for testing structural validation logic which doesn't verify
    /// the BLS signature (that's done asynchronously via Action::VerifyCycleProof).
    fn make_test_cycle_proof(winner_tx_hash: Hash) -> hyperscale_types::CycleProof {
        use hyperscale_types::{CommitmentProof, CycleProof, ShardGroupId, SignerBitfield};
        use std::sync::Arc;

        let commitment_proof = CommitmentProof {
            tx_hash: winner_tx_hash,
            source_shard: ShardGroupId(1),
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            block_height: BlockHeight(1),
            block_timestamp: 1000,
            entries: Arc::new(vec![]),
        };
        CycleProof::new(winner_tx_hash, commitment_proof)
    }

    /// Create a test deferral with a minimal proof.
    fn make_test_deferral(loser_tx: Hash, winner_tx: Hash) -> TransactionDefer {
        use hyperscale_types::DeferReason;
        TransactionDefer {
            tx_hash: loser_tx,
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: winner_tx,
            },
            block_height: BlockHeight(0),
            proof: make_test_cycle_proof(winner_tx),
        }
    }

    fn make_test_block(
        height: u64,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        certificates: Vec<hyperscale_types::TransactionCertificate>,
    ) -> Block {
        Block {
            header: make_header_at_height(height, 100_000),
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            certificates: certificates.into_iter().map(Arc::new).collect(),
            deferred,
            aborted,
            commitment_proofs: HashMap::new(),
        }
    }

    #[test]
    fn test_validate_deferral_hash_ordering() {
        let state = make_test_state();

        // Use raw hash bytes to control ordering deterministically
        // Loser must have higher hash, winner must have lower hash
        // Hash comparison is derived lexicographically from underlying bytes
        let mut loser_bytes = [0xFFu8; 32]; // All 0xFF = max hash
        let mut winner_bytes = [0x00u8; 32]; // All 0x00 = min hash
        loser_bytes[0] = 0x01; // Ensure not all same bytes
        winner_bytes[0] = 0x00;

        let loser_hash = Hash::from_hash_bytes(&loser_bytes);
        let winner_hash = Hash::from_hash_bytes(&winner_bytes);

        // Verify ordering assumption
        assert!(
            loser_hash > winner_hash,
            "Test setup: loser_hash must be > winner_hash"
        );

        // Valid: loser (higher) deferred to winner (lower)
        let valid_deferral = TransactionDefer {
            tx_hash: loser_hash,
            reason: hyperscale_types::DeferReason::LivelockCycle {
                winner_tx_hash: winner_hash,
            },
            block_height: BlockHeight(5),
            proof: make_test_cycle_proof(winner_hash),
        };
        let block = make_test_block(5, vec![valid_deferral], vec![], vec![]);
        assert!(state.validate_deferrals_and_aborts(&block).is_ok());

        // Invalid: winner (lower) cannot be deferred - hash ordering violated
        let invalid_deferral = TransactionDefer {
            tx_hash: winner_hash,
            reason: hyperscale_types::DeferReason::LivelockCycle {
                winner_tx_hash: loser_hash,
            },
            block_height: BlockHeight(5),
            proof: make_test_cycle_proof(loser_hash),
        };
        let block = make_test_block(5, vec![invalid_deferral], vec![], vec![]);
        let result = state.validate_deferrals_and_aborts(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be >"));
    }

    #[test]
    fn test_validate_deferral_not_stale_winner() {
        let state = make_test_state();

        // Use raw hash bytes for deterministic ordering
        let loser_bytes = [0xFFu8; 32]; // Higher hash
        let winner_bytes = [0x00u8; 32]; // Lower hash
        let loser_hash = Hash::from_hash_bytes(&loser_bytes);
        let winner_hash = Hash::from_hash_bytes(&winner_bytes);

        // Create a certificate for the winner (means winner already completed)
        let winner_cert = hyperscale_types::TransactionCertificate {
            transaction_hash: winner_hash,
            decision: hyperscale_types::TransactionDecision::Accept,
            shard_proofs: std::collections::BTreeMap::new(),
        };

        // Invalid: deferral when winner already has certificate in same block
        let deferral = TransactionDefer {
            tx_hash: loser_hash,
            reason: hyperscale_types::DeferReason::LivelockCycle {
                winner_tx_hash: winner_hash,
            },
            block_height: BlockHeight(5),
            proof: make_test_cycle_proof(winner_hash),
        };
        let block = make_test_block(5, vec![deferral], vec![], vec![winner_cert]);
        let result = state.validate_deferrals_and_aborts(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stale"));
    }

    #[test]
    fn test_validate_deferral_not_stale_loser() {
        let state = make_test_state();

        // Use raw hash bytes for deterministic ordering
        let loser_bytes = [0xFFu8; 32]; // Higher hash
        let winner_bytes = [0x00u8; 32]; // Lower hash
        let loser_hash = Hash::from_hash_bytes(&loser_bytes);
        let winner_hash = Hash::from_hash_bytes(&winner_bytes);

        // Create a certificate for the loser (means loser already completed)
        let loser_cert = hyperscale_types::TransactionCertificate {
            transaction_hash: loser_hash,
            decision: hyperscale_types::TransactionDecision::Accept,
            shard_proofs: std::collections::BTreeMap::new(),
        };

        // Invalid: deferral when loser already has certificate in same block
        let deferral = TransactionDefer {
            tx_hash: loser_hash,
            reason: hyperscale_types::DeferReason::LivelockCycle {
                winner_tx_hash: winner_hash,
            },
            block_height: BlockHeight(5),
            proof: make_test_cycle_proof(winner_hash),
        };
        let block = make_test_block(5, vec![deferral], vec![], vec![loser_cert]);
        let result = state.validate_deferrals_and_aborts(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stale"));
    }

    #[test]
    fn test_validate_deferral_proof_winner_hash_mismatch() {
        let state = make_test_state();

        // Use raw hash bytes for deterministic ordering
        let loser_bytes = [0xFFu8; 32]; // Higher hash
        let winner_bytes = [0x00u8; 32]; // Lower hash
        let other_bytes = [0x50u8; 32]; // Some other hash
        let loser_hash = Hash::from_hash_bytes(&loser_bytes);
        let winner_hash = Hash::from_hash_bytes(&winner_bytes);
        let other_hash = Hash::from_hash_bytes(&other_bytes);

        // Invalid: CycleProof has different winner than deferral reason
        let deferral = TransactionDefer {
            tx_hash: loser_hash,
            reason: hyperscale_types::DeferReason::LivelockCycle {
                winner_tx_hash: winner_hash,
            },
            block_height: BlockHeight(5),
            proof: make_test_cycle_proof(other_hash), // Wrong winner!
        };
        let block = make_test_block(5, vec![deferral], vec![], vec![]);
        let result = state.validate_deferrals_and_aborts(&block);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("CycleProof winner"),
            "Error should mention CycleProof winner mismatch"
        );
    }

    #[test]
    fn test_validate_abort_execution_timeout() {
        let state = make_test_state();

        // Valid: timeout at block 35 for TX committed at block 1
        let valid_abort = TransactionAbort {
            tx_hash: Hash::from_bytes(b"tx1"),
            reason: hyperscale_types::AbortReason::ExecutionTimeout {
                committed_at: BlockHeight(1),
            },
            block_height: BlockHeight(35),
        };
        let block = make_test_block(35, vec![], vec![valid_abort], vec![]);
        assert!(state.validate_deferrals_and_aborts(&block).is_ok());

        // Invalid: block_height < committed_at
        let invalid_abort = TransactionAbort {
            tx_hash: Hash::from_bytes(b"tx2"),
            reason: hyperscale_types::AbortReason::ExecutionTimeout {
                committed_at: BlockHeight(100),
            },
            block_height: BlockHeight(50),
        };
        let block = make_test_block(50, vec![], vec![invalid_abort], vec![]);
        let result = state.validate_deferrals_and_aborts(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("block_height"));
    }

    #[test]
    fn test_validate_abort_too_many_retries() {
        let state = make_test_state();

        // Valid: retry_count > 0
        let valid_abort = TransactionAbort {
            tx_hash: Hash::from_bytes(b"tx1"),
            reason: hyperscale_types::AbortReason::TooManyRetries { retry_count: 3 },
            block_height: BlockHeight(10),
        };
        let block = make_test_block(10, vec![], vec![valid_abort], vec![]);
        assert!(state.validate_deferrals_and_aborts(&block).is_ok());

        // Invalid: retry_count = 0
        let invalid_abort = TransactionAbort {
            tx_hash: Hash::from_bytes(b"tx2"),
            reason: hyperscale_types::AbortReason::TooManyRetries { retry_count: 0 },
            block_height: BlockHeight(10),
        };
        let block = make_test_block(10, vec![], vec![invalid_abort], vec![]);
        let result = state.validate_deferrals_and_aborts(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("retry_count 0"));
    }

    #[test]
    fn test_validate_abort_execution_rejected() {
        let state = make_test_state();

        // ExecutionRejected always passes (no structural validation)
        let abort = TransactionAbort {
            tx_hash: Hash::from_bytes(b"tx1"),
            reason: hyperscale_types::AbortReason::ExecutionRejected {
                reason: "insufficient balance".to_string(),
            },
            block_height: BlockHeight(10),
        };
        let block = make_test_block(10, vec![], vec![abort], vec![]);
        assert!(state.validate_deferrals_and_aborts(&block).is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote Locking Safety Tests
    // ═══════════════════════════════════════════════════════════════════════════

    /// Helper to create a state with multiple validators for vote testing
    fn make_multi_validator_state() -> (BftState, Vec<Bls12381G1PrivateKey>) {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));
        let state = BftState::new(
            0,
            {
                let key_bytes = keys[0].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );
        (state, keys)
    }

    #[test]
    fn test_vote_locking_prevents_voting_for_different_block_at_same_height() {
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 1u64;
        let round_0 = 0u64;
        let round_1 = 1u64;

        // Create two different blocks at the same height
        let block_a = BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(1),
            timestamp: 100_000,
            round: round_0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        let block_a_hash = block_a.hash();

        let block_b = BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(2),
            timestamp: 100_001, // Different timestamp = different hash
            round: round_1,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        let block_b_hash = block_b.hash();

        // Vote for block A at height 1, round 0
        let actions = state.try_vote_on_block(block_a_hash, height, round_0);
        assert!(
            !actions.is_empty(),
            "Should be able to vote for first block"
        );

        // Verify we recorded the vote
        assert!(state.voted_heights.contains_key(&height));
        assert_eq!(state.voted_heights.get(&height).unwrap().0, block_a_hash);

        // Try to vote for block B at height 1, round 1 (different block, same height)
        // This should be REJECTED due to vote locking
        let actions = state.try_vote_on_block(block_b_hash, height, round_1);
        assert!(
            actions.is_empty(),
            "Vote locking should prevent voting for different block at same height"
        );

        // Verify we're still locked to block A
        assert_eq!(state.voted_heights.get(&height).unwrap().0, block_a_hash);
    }

    #[test]
    fn test_vote_locking_allows_revoting_same_block() {
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 1u64;
        let block = BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(1),
            timestamp: 100_000,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        let block_hash = block.hash();

        // Vote for block at round 0
        let actions = state.try_vote_on_block(block_hash, height, 0);
        assert!(!actions.is_empty(), "Should vote for block");

        // Try to vote for SAME block at round 1 (after view change)
        // This should return empty (already voted) but NOT log a warning
        let actions = state.try_vote_on_block(block_hash, height, 1);
        assert!(
            actions.is_empty(),
            "Should not re-broadcast vote for same block"
        );

        // But we should still be locked to the block
        assert_eq!(state.voted_heights.get(&height).unwrap().0, block_hash);
    }

    #[test]
    fn test_vote_locking_cleaned_up_on_commit() {
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        // Vote at heights 1, 2, 3
        for height in 1..=3 {
            let block = BlockHeader {
                height: BlockHeight(height),
                parent_hash: Hash::from_bytes(b"parent"),
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId(1),
                timestamp: 100_000,
                round: 0,
                is_fallback: false,
                state_root: Hash::ZERO,
                state_version: 0,
                transaction_root: Hash::ZERO,
            };
            state.try_vote_on_block(block.hash(), height, 0);
        }

        assert_eq!(state.voted_heights.len(), 3);

        // Simulate commit at height 2
        state.cleanup_old_state(2);

        // Only height 3 should remain
        assert_eq!(state.voted_heights.len(), 1);
        assert!(state.voted_heights.contains_key(&3));
        assert!(!state.voted_heights.contains_key(&1));
        assert!(!state.voted_heights.contains_key(&2));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Cross-VoteSet Equivocation Detection Tests
    // ═══════════════════════════════════════════════════════════════════════════
    //
    // Equivocation detection happens in on_qc_result AFTER signature verification.
    // This prevents a DoS attack where a malicious node forges votes claiming to be
    // from a legitimate validator, which would block the real validator's votes.
    //
    // These tests verify the detection logic by directly calling on_qc_result with
    // simulated verified votes.

    #[test]
    fn test_equivocation_detected_same_height_same_round_different_block() {
        // Byzantine validator votes for two different blocks at the same (height, round).
        // The second vote should be detected as equivocation.
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 5u64;
        let round = 2u64;
        let byzantine_voter = ValidatorId(2);

        let block_a = Hash::from_bytes(b"block_a_at_height_5");
        let block_b = Hash::from_bytes(b"block_b_at_height_5");

        // First verified vote for block A - simulate on_qc_result recording it
        let vote_a = BlockVote {
            block_hash: block_a,
            height: BlockHeight(height),
            round,
            voter: byzantine_voter,
            signature: zero_bls_signature(),
            timestamp: 100_000,
        };

        // Simulate verified vote being processed (no QC formed)
        let verified_votes_a = vec![(0usize, vote_a, 1u64)];
        let _actions = state.on_qc_result(block_a, None, verified_votes_a);

        // Verify first vote was recorded
        assert!(state
            .received_votes_by_height
            .contains_key(&(height, byzantine_voter)));
        let (recorded_hash, recorded_round) = state
            .received_votes_by_height
            .get(&(height, byzantine_voter))
            .unwrap();
        assert_eq!(*recorded_hash, block_a);
        assert_eq!(*recorded_round, round);

        // Second verified vote for DIFFERENT block at SAME height and round - equivocation!
        let vote_b = BlockVote {
            block_hash: block_b,
            height: BlockHeight(height),
            round,
            voter: byzantine_voter,
            signature: zero_bls_signature(),
            timestamp: 100_000,
        };

        // Process second verified vote - equivocation should be detected and logged
        let verified_votes_b = vec![(0usize, vote_b, 1u64)];
        let _actions = state.on_qc_result(block_b, None, verified_votes_b);

        // Original vote should still be recorded (equivocating vote skipped)
        let (recorded_hash, _) = state
            .received_votes_by_height
            .get(&(height, byzantine_voter))
            .unwrap();
        assert_eq!(
            *recorded_hash, block_a,
            "Original vote should not be overwritten by equivocating vote"
        );
    }

    #[test]
    fn test_no_equivocation_same_height_different_round() {
        // Validator votes for different blocks at same height but different rounds.
        // This is ALLOWED per HotStuff-2 (unlock on round advancement).
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 5u64;
        let voter = ValidatorId(2);

        let block_a = Hash::from_bytes(b"block_a_at_height_5");
        let block_b = Hash::from_bytes(b"block_b_at_height_5");

        // Vote for block A at round 0
        let vote_a = BlockVote {
            block_hash: block_a,
            height: BlockHeight(height),
            round: 0,
            voter,
            signature: zero_bls_signature(),
            timestamp: 100_000,
        };
        let verified_votes_a = vec![(0usize, vote_a, 1u64)];
        let _actions = state.on_qc_result(block_a, None, verified_votes_a);

        // Vote for DIFFERENT block at DIFFERENT round - this is allowed!
        let vote_b = BlockVote {
            block_hash: block_b,
            height: BlockHeight(height),
            round: 1, // Different round
            voter,
            signature: zero_bls_signature(),
            timestamp: 100_000,
        };
        let verified_votes_b = vec![(0usize, vote_b, 1u64)];
        let _actions = state.on_qc_result(block_b, None, verified_votes_b);

        // Second vote should be recorded (overwrites first since different round is allowed)
        let (recorded_hash, recorded_round) = state
            .received_votes_by_height
            .get(&(height, voter))
            .unwrap();
        assert_eq!(
            *recorded_hash, block_b,
            "Vote at higher round should be recorded"
        );
        assert_eq!(*recorded_round, 1);
    }

    #[test]
    fn test_equivocation_detection_independent_per_height() {
        // Votes at different heights should not interfere with each other.
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let voter = ValidatorId(2);
        let round = 0u64;

        // Vote for block at height 5
        let vote_h5 = BlockVote {
            block_hash: Hash::from_bytes(b"block_at_height_5"),
            height: BlockHeight(5),
            round,
            voter,
            signature: zero_bls_signature(),
            timestamp: 100_000,
        };
        let verified_votes_h5 = vec![(0usize, vote_h5.clone(), 1u64)];
        let _actions = state.on_qc_result(vote_h5.block_hash, None, verified_votes_h5);

        // Vote for DIFFERENT block at height 6 - this is fine (different height)
        let vote_h6 = BlockVote {
            block_hash: Hash::from_bytes(b"different_block_at_height_6"),
            height: BlockHeight(6),
            round,
            voter,
            signature: zero_bls_signature(),
            timestamp: 100_000,
        };
        let verified_votes_h6 = vec![(0usize, vote_h6.clone(), 1u64)];
        let _actions = state.on_qc_result(vote_h6.block_hash, None, verified_votes_h6);

        // Both should be recorded
        assert!(state.received_votes_by_height.contains_key(&(5, voter)));
        assert!(state.received_votes_by_height.contains_key(&(6, voter)));
    }

    #[test]
    fn test_forged_vote_cannot_block_legitimate_validator() {
        // This is the critical security test: a malicious node cannot block
        // a legitimate validator by forging votes before verification.
        //
        // Scenario:
        // 1. Malicious node sends forged vote claiming to be from ValidatorX for block A
        // 2. Forged vote gets buffered (unverified) - NOT recorded in received_votes_by_height
        // 3. Real vote from ValidatorX for block B arrives
        // 4. Real vote gets buffered (unverified)
        // 5. Verification runs - forged vote fails, real vote passes
        // 6. Only real vote is recorded - no equivocation detected
        //
        // We test step 5-6 by simulating on_qc_result with only the legitimate vote.
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 5u64;
        let round = 0u64;
        let legitimate_voter = ValidatorId(2);

        let block_b = Hash::from_bytes(b"legitimate_block");

        // Only the legitimate vote passes verification
        let legitimate_vote = BlockVote {
            block_hash: block_b,
            height: BlockHeight(height),
            round,
            voter: legitimate_voter,
            signature: zero_bls_signature(), // In reality, this would have valid signature
            timestamp: 100_000,
        };

        // Simulate verification result - only legitimate vote verified
        let verified_votes = vec![(0usize, legitimate_vote, 1u64)];
        let _actions = state.on_qc_result(block_b, None, verified_votes);

        // Legitimate vote should be recorded
        assert!(state
            .received_votes_by_height
            .contains_key(&(height, legitimate_voter)));
        let (recorded_hash, _) = state
            .received_votes_by_height
            .get(&(height, legitimate_voter))
            .unwrap();
        assert_eq!(
            *recorded_hash, block_b,
            "Legitimate vote should be recorded"
        );
    }

    #[test]
    fn test_received_votes_cleaned_up_on_commit() {
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        // Record votes at heights 1, 2, 3 from different validators
        for height in 1..=3u64 {
            let voter = ValidatorId(height);
            let block_hash = Hash::from_bytes(format!("block_{}", height).as_bytes());
            state
                .received_votes_by_height
                .insert((height, voter), (block_hash, 0)); // round 0
        }

        assert_eq!(state.received_votes_by_height.len(), 3);

        // Commit at height 2
        state.cleanup_old_state(2);

        // Only height 3 votes should remain
        assert_eq!(state.received_votes_by_height.len(), 1);
        assert!(state
            .received_votes_by_height
            .contains_key(&(3, ValidatorId(3))));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Re-proposal After View Change Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_repropose_locked_block_keeps_original_round() {
        // Scenario:
        // 1. Validator 1 proposes block at (height=1, round=0)
        // 2. Validator 0 receives it, adds to pending_blocks, and votes
        // 3. View change occurs, validator 0 becomes leader at round=31
        // 4. Validator 0 re-proposes the locked block
        // 5. The re-proposed block should keep round=0 (not change to 31)
        //    so the block hash stays the same

        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 1u64;
        let original_round = 0u64;
        let view_change_round = 31u64;

        // Create original block from validator 1 at round 0
        // proposer_for(1, 0) = (1 + 0) % 4 = 1 = ValidatorId(1)
        let original_header = BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(1),
            timestamp: 100_000,
            round: original_round,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        let original_block_hash = original_header.hash();

        // Add to pending_blocks (simulating receiving the header)
        let pending = PendingBlock::full(
            original_header.clone(),
            vec![], // retry_hashes
            vec![], // priority_hashes
            vec![], // tx_hashes
            vec![], // cert_hashes
            vec![], // deferred
            vec![], // aborted
        );
        state.pending_blocks.insert(original_block_hash, pending);

        // Simulate voting for this block
        state
            .voted_heights
            .insert(height, (original_block_hash, original_round));

        // Now call repropose_locked_block (simulating view change where we're the new leader)
        let actions = state.repropose_locked_block(original_block_hash, height);

        // Should have broadcast action
        let broadcast_action = actions
            .iter()
            .find(|a| matches!(a, Action::BroadcastBlockHeader { .. }));
        assert!(
            broadcast_action.is_some(),
            "Should broadcast the re-proposed block"
        );

        // Extract the header from the broadcast
        if let Some(Action::BroadcastBlockHeader { header: gossip, .. }) = broadcast_action {
            let reproposed_header = gossip.header();

            // CRITICAL: The round should be the ORIGINAL round, not the view change round
            assert_eq!(
                reproposed_header.round, original_round,
                "Re-proposed block should keep original round ({}), not view change round ({})",
                original_round, view_change_round
            );

            // The block hash should be unchanged
            assert_eq!(
                reproposed_header.hash(),
                original_block_hash,
                "Re-proposed block hash should match original"
            );

            // The proposer should be the original proposer
            assert_eq!(
                reproposed_header.proposer,
                ValidatorId(1),
                "Re-proposed block should keep original proposer"
            );
        }
    }

    #[test]
    fn test_reproposed_block_passes_validation() {
        // Verify that a re-proposed block with original round passes validate_header
        // This is the receiving validator's perspective

        let (state, _keys) = make_multi_validator_state();

        let height = 1u64;
        let original_round = 0u64;

        // Create block with original proposer for (height=1, round=0)
        // proposer_for(1, 0) = (1 + 0) % 4 = 1 = ValidatorId(1)
        let header = BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(1),
            timestamp: (state.now.as_millis() as u64), // Current time for timestamp validation
            round: original_round,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        // Even though the receiving validator might be at view=31,
        // validation should pass because:
        // - proposer_for(1, 0) = ValidatorId(1) matches header.proposer
        let result = state.validate_header(&header);
        assert!(
            result.is_ok(),
            "Re-proposed block with original round should pass validation: {:?}",
            result
        );
    }

    #[test]
    fn test_reproposed_block_with_wrong_proposer_fails_validation() {
        // If someone tries to re-propose with a different proposer, it should fail

        let (state, _keys) = make_multi_validator_state();

        let height = 1u64;

        // Create block claiming round=0 but with wrong proposer
        // proposer_for(1, 0) = ValidatorId(1), but we claim ValidatorId(3)
        let header = BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(3), // Wrong! Should be ValidatorId(1) for round=0
            timestamp: (state.now.as_millis() as u64),
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        let result = state.validate_header(&header);
        assert!(
            result.is_err(),
            "Block with wrong proposer for round should fail validation"
        );
        assert!(
            result.unwrap_err().contains("wrong proposer"),
            "Error should mention wrong proposer"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Extended View Change Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_multiple_consecutive_view_changes_unlock_and_revote() {
        // Scenario: Multiple view changes occur before any QC forms.
        // Each view change unlocks votes at the current height and then
        // (if we're the proposer) creates a new fallback block and votes for it.
        //
        // Note: advance_round unlocks votes at the height we're PROPOSING for,
        // which is latest_qc.height + 1 (or committed_height + 1 if no QC).
        // Without any QC, we're always proposing for height 1.
        //
        // The flow is: unlock -> check if proposer -> create fallback -> vote for it
        // So the old vote is replaced with a new vote for the fallback block.
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        let height = 1u64;

        // Round 0: Vote for block A at height 1
        let block_a = Hash::from_bytes(b"block_a_round_0");
        state.voted_heights.insert(height, (block_a, 0));
        assert!(state.voted_heights.contains_key(&height));

        // Round 1: First view change
        // Validator 0 is proposer for (1, 1) since (1+1)%4 = 2... wait no.
        // make_test_state creates a validator with ValidatorId(0).
        // proposer_for(1, 0) = (1+0)%4 = 1 = ValidatorId(1)
        // proposer_for(1, 1) = (1+1)%4 = 2 = ValidatorId(2)
        // So ValidatorId(0) is NOT the proposer at round 1.
        state.view = 0; // Reset for clean test
        let _actions = state.advance_round();
        assert_eq!(state.view, 1);
        // Vote lock should be cleared (no QC at height 1, latest_qc_height = 0 < 1)
        // Since we're NOT the proposer, no new vote is created
        assert!(
            !state.voted_heights.contains_key(&height),
            "Vote lock should be cleared after first view change (not proposer)"
        );

        // Simulate voting for block B at round 1 (externally, as if we received a proposal)
        let block_b = Hash::from_bytes(b"block_b_round_1");
        state.voted_heights.insert(height, (block_b, 1));

        // Round 2: Second view change - not proposer, should unlock
        // proposer_for(1, 2) = (1+2)%4 = 3 = ValidatorId(3)
        let _actions = state.advance_round();
        assert_eq!(state.view, 2);
        assert!(
            !state.voted_heights.contains_key(&height),
            "Vote lock should be cleared after second view change (not proposer)"
        );

        // Simulate voting for block C at round 2
        let block_c = Hash::from_bytes(b"block_c_round_2");
        state.voted_heights.insert(height, (block_c, 2));

        // Round 3: Third view change - not proposer, should unlock
        // proposer_for(1, 3) = (1+3)%4 = 0 = ValidatorId(0) - WE ARE THE PROPOSER!
        let actions = state.advance_round();
        assert_eq!(state.view, 3);
        // Since we're the proposer, we create a fallback block and vote for it
        // So there WILL be a vote at height 1 (for the new fallback block)
        assert!(
            state.voted_heights.contains_key(&height),
            "Should have a new vote at height 1 (we're the proposer, voted for fallback)"
        );
        let (new_hash, new_round) = state.voted_heights.get(&height).unwrap();
        assert_eq!(*new_round, 3, "Vote should be at round 3");
        assert_ne!(
            *new_hash, block_c,
            "Vote should be for new fallback, not block C"
        );

        // Verify we broadcast a fallback block
        let has_broadcast = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastBlockHeader { .. }));
        assert!(has_broadcast, "Should broadcast fallback block");
    }

    #[test]
    fn test_view_change_does_not_unlock_lower_heights() {
        // Scenario: We have a QC at height 1, so we're now proposing for height 2.
        // advance_round should only try to unlock at height 2, not at height 1.
        // Vote locks at lower heights are preserved (they'll be cleaned up on commit).
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        // Set up: We have a QC at height 1 (meaning consensus decided for height 1)
        let qc_block = Hash::from_bytes(b"qc_block_at_1");
        let qc = QuorumCertificate {
            block_hash: qc_block,
            height: BlockHeight(1),
            parent_block_hash: Hash::ZERO,
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };
        state.latest_qc = Some(qc);

        // We have votes at heights 1 and 2
        state.voted_heights.insert(1, (qc_block, 0));
        state
            .voted_heights
            .insert(2, (Hash::from_bytes(b"block_at_2"), 0));

        // View change advances round. With QC at height 1, we propose for height 2.
        // The unlock check is: latest_qc_height (1) < height (2)? Yes.
        // So it unlocks at height 2, NOT at height 1.
        let _actions = state.advance_round();

        // Vote at height 1 should still be there (advance_round doesn't touch it)
        assert!(
            state.voted_heights.contains_key(&1),
            "Vote lock at height 1 should be preserved (advance_round only unlocks at proposal height)"
        );

        // Vote at height 2 should be cleared (we're proposing for height 2, no QC there)
        assert!(
            !state.voted_heights.contains_key(&2),
            "Vote lock at height 2 should be cleared (no QC at height 2)"
        );
    }

    #[test]
    fn test_qc_arriving_during_view_change_scenario() {
        // Scenario: We're in the middle of view changes, then receive a QC.
        // The QC should unlock votes at and below its height.
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        // Set up vote locks at multiple heights
        state
            .voted_heights
            .insert(1, (Hash::from_bytes(b"block_1"), 0));
        state
            .voted_heights
            .insert(2, (Hash::from_bytes(b"block_2"), 0));
        state
            .voted_heights
            .insert(3, (Hash::from_bytes(b"block_3"), 0));

        // Simulate being at round 5 (multiple view changes happened)
        state.view = 5;

        // Now receive a QC at height 2 (maybe from a different validator's proposal)
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"qc_block_2"),
            height: BlockHeight(2),
            parent_block_hash: Hash::from_bytes(b"parent_1"),
            round: 3, // Different round from our votes
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        state.maybe_unlock_for_qc(&qc);

        // Heights 1 and 2 should be unlocked
        assert!(
            !state.voted_heights.contains_key(&1),
            "Height 1 should be unlocked by QC at height 2"
        );
        assert!(
            !state.voted_heights.contains_key(&2),
            "Height 2 should be unlocked by QC at height 2"
        );
        // Height 3 should remain locked
        assert!(
            state.voted_heights.contains_key(&3),
            "Height 3 should remain locked"
        );
    }

    #[test]
    fn test_unlock_for_qc_at_same_height_different_block() {
        // Scenario: We voted for block A at height H, but QC forms for block B at height H.
        // This proves B won consensus, so our lock on A is now irrelevant and safe to remove.
        let mut state = make_test_state();

        let block_a = Hash::from_bytes(b"block_a");
        let block_b = Hash::from_bytes(b"block_b");
        let height = 5u64;

        // We voted for block A
        state.voted_heights.insert(height, (block_a, 0));

        // QC forms for block B (different block at same height)
        let qc = QuorumCertificate {
            block_hash: block_b, // Different from our vote!
            height: BlockHeight(height),
            parent_block_hash: Hash::from_bytes(b"parent"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        state.maybe_unlock_for_qc(&qc);

        // Our vote lock should be removed - block A can never get a QC now
        // (2f+1 voted for B, only f+1 honest validators could have voted for A)
        assert!(
            !state.voted_heights.contains_key(&height),
            "Vote lock at height {} should be removed when QC forms for different block",
            height
        );
    }

    #[test]
    fn test_safety_cannot_vote_for_conflicting_block_after_voting() {
        // This is the core safety test: once we vote for block A at height H,
        // we must NEVER vote for a different block B at height H (in any round).
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 1u64;
        let block_a = Hash::from_bytes(b"block_a");
        let block_b = Hash::from_bytes(b"block_b");

        // Vote for block A at height 1
        state.voted_heights.insert(height, (block_a, 0));

        // Try to vote for block B at the same height - should be blocked
        let actions = state.try_vote_on_block(block_b, height, 1); // Different round doesn't help

        assert!(
            actions.is_empty(),
            "Should not be able to vote for different block at same height"
        );
        assert_eq!(
            state.voted_heights.get(&height),
            Some(&(block_a, 0)),
            "Vote lock should still point to original block"
        );
    }

    #[test]
    fn test_can_vote_for_same_block_at_different_round() {
        // If we already voted for block A at round 0, we can "re-vote" for
        // block A at round 1 (though it's a no-op since same block).
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 1u64;
        let block_a = Hash::from_bytes(b"block_a");

        // Vote for block A at round 0
        state.voted_heights.insert(height, (block_a, 0));

        // Try to vote for same block A at round 1 - should be a no-op (already voted)
        let actions = state.try_vote_on_block(block_a, height, 1);

        // Should be empty because we already voted for this block
        assert!(
            actions.is_empty(),
            "Re-voting for same block should be a no-op"
        );
    }

    #[test]
    fn test_view_change_with_prior_vote_creates_fallback() {
        // Scenario:
        // 1. We vote for block at (height=1, round=0)
        // 2. View change to round where we become proposer
        // 3. Since no QC formed at height 1, our vote is unlocked
        // 4. We create a fresh fallback block (not re-propose)
        //
        // This is the correct HotStuff-2 behavior: on view change without QC,
        // validators are free to vote for new blocks. The new proposer creates
        // a fallback block to ensure liveness.
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        // Validator 0 will be proposer at (height=1, round=3): (1+3)%4 = 0
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));
        let mut state = BftState::new(
            0,
            {
                let key_bytes = keys[0].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );
        state.set_time(Duration::from_secs(100));

        // Create a block from round 0 that we voted for
        let original_header = BlockHeader {
            height: BlockHeight(1),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(1), // proposer_for(1, 0) = 1
            timestamp: 100_000,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        let original_block_hash = original_header.hash();

        // Add to pending blocks and vote for it
        let pending = PendingBlock::new(original_header, vec![], vec![], vec![], vec![]);
        state.pending_blocks.insert(original_block_hash, pending);
        state.voted_heights.insert(1, (original_block_hash, 0));

        // Advance to round 3 where we become the proposer
        // Since no QC at height 1, vote lock is cleared, then we create fallback
        state.view = 2; // Will become 3 after advance_round

        let actions = state.advance_round();

        // The old vote should be replaced with a vote for the new fallback block.
        // advance_round: 1) unlocks at height 1, 2) creates fallback, 3) votes for it
        assert!(
            state.voted_heights.contains_key(&1),
            "Should have a new vote at height 1 (for the fallback block)"
        );
        let (new_block_hash, new_round) = state.voted_heights.get(&1).unwrap();
        assert_ne!(
            *new_block_hash, original_block_hash,
            "Vote should be for the new fallback block, not the original"
        );
        assert_eq!(*new_round, 3, "Vote should be at round 3");

        // Should have broadcast action (fallback block)
        let broadcast_action = actions
            .iter()
            .find(|a| matches!(a, Action::BroadcastBlockHeader { .. }));
        assert!(
            broadcast_action.is_some(),
            "Should broadcast fallback block when becoming proposer after view change"
        );

        // Verify it's a fallback block (not the original)
        if let Some(Action::BroadcastBlockHeader { header: gossip, .. }) = broadcast_action {
            assert!(gossip.header().is_fallback, "Should be a fallback block");
            assert_eq!(
                gossip.header().round,
                3,
                "Fallback block should be at new round"
            );
            assert_ne!(
                gossip.header().hash(),
                original_block_hash,
                "Fallback block should be different from original"
            );
            // Verify the fallback block hash matches what we voted for
            assert_eq!(
                gossip.header().hash(),
                *new_block_hash,
                "Fallback block hash should match our vote"
            );
        }

        // Should have vote action (we vote for our own fallback)
        let has_vote = actions
            .iter()
            .any(|a| matches!(a, Action::PersistAndBroadcastVote { .. }));
        assert!(has_vote, "Should vote for own fallback block");
    }

    #[test]
    fn test_view_change_without_lock_creates_fallback() {
        // Scenario: View change when we haven't voted at this height yet.
        // Should create a fallback block (empty block).
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);

        // Validator 0 will be proposer at (height=1, round=3): (1+3)%4 = 0
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));
        let mut state = BftState::new(
            0,
            {
                let key_bytes = keys[0].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );
        state.set_time(Duration::from_secs(100));

        // No vote lock at height 1 - we haven't voted yet
        assert!(!state.voted_heights.contains_key(&1));

        // Advance to round 3 where we become proposer
        state.view = 2;
        let actions = state.advance_round();

        // Should create and broadcast a fallback block
        let broadcast_action = actions
            .iter()
            .find(|a| matches!(a, Action::BroadcastBlockHeader { .. }));
        assert!(
            broadcast_action.is_some(),
            "Should broadcast fallback block"
        );

        // Extract and verify it's a fallback block
        if let Some(Action::BroadcastBlockHeader { header: gossip, .. }) = broadcast_action {
            assert!(
                gossip.header().is_fallback,
                "Block should be marked as fallback"
            );
            assert_eq!(gossip.header().round, 3, "Block should be at round 3");
        }

        // Should also have a vote action (we vote for our own fallback block)
        let has_vote = actions
            .iter()
            .any(|a| matches!(a, Action::PersistAndBroadcastVote { .. }));
        assert!(has_vote, "Should create vote for own fallback block");
    }

    #[test]
    fn test_multiple_heights_vote_locking_independent() {
        // Verify that vote locks at different heights are independent.
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        let block_h1 = Hash::from_bytes(b"block_height_1");
        let block_h2 = Hash::from_bytes(b"block_height_2");
        let block_h3 = Hash::from_bytes(b"block_height_3");

        // Vote at multiple heights
        state.voted_heights.insert(1, (block_h1, 0));
        state.voted_heights.insert(2, (block_h2, 0));
        state.voted_heights.insert(3, (block_h3, 0));

        // QC at height 1 should only unlock height 1
        let qc_h1 = QuorumCertificate {
            block_hash: block_h1,
            height: BlockHeight(1),
            parent_block_hash: Hash::ZERO,
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };
        state.maybe_unlock_for_qc(&qc_h1);

        assert!(
            !state.voted_heights.contains_key(&1),
            "Height 1 should be unlocked"
        );
        assert!(
            state.voted_heights.contains_key(&2),
            "Height 2 should remain locked"
        );
        assert!(
            state.voted_heights.contains_key(&3),
            "Height 3 should remain locked"
        );
    }

    #[test]
    fn test_genesis_qc_does_not_unlock() {
        // Genesis QC should not trigger any unlocks (edge case).
        let mut state = make_test_state();

        state
            .voted_heights
            .insert(1, (Hash::from_bytes(b"block_1"), 0));

        let genesis_qc = QuorumCertificate::genesis();
        state.maybe_unlock_for_qc(&genesis_qc);

        assert!(
            state.voted_heights.contains_key(&1),
            "Genesis QC should not unlock any votes"
        );
    }

    #[test]
    fn test_clear_vote_tracking_for_height() {
        // Test the helper function that clears vote tracking during HotStuff-2 unlock.
        let mut state = make_test_state();

        // Add vote tracking for multiple validators at height 5
        let height = 5u64;
        state
            .received_votes_by_height
            .insert((height, ValidatorId(0)), (Hash::from_bytes(b"block_a"), 0));
        state
            .received_votes_by_height
            .insert((height, ValidatorId(1)), (Hash::from_bytes(b"block_b"), 0));
        state
            .received_votes_by_height
            .insert((height, ValidatorId(2)), (Hash::from_bytes(b"block_a"), 1));
        // Also add tracking at different height
        state
            .received_votes_by_height
            .insert((6, ValidatorId(0)), (Hash::from_bytes(b"block_c"), 0));

        // Clear tracking for height 5, advancing to round 2
        let cleared = state.clear_vote_tracking_for_height(height, 2);

        assert_eq!(cleared, 3, "Should clear 3 entries at height 5");
        assert!(
            !state
                .received_votes_by_height
                .contains_key(&(5, ValidatorId(0))),
            "Height 5 entries should be cleared"
        );
        assert!(
            state
                .received_votes_by_height
                .contains_key(&(6, ValidatorId(0))),
            "Height 6 entries should remain"
        );
    }

    #[test]
    fn test_clear_vote_tracking_preserves_current_round_vote_sets() {
        // Test that vote sets at the current/higher round are preserved.
        // This is critical to prevent losing accumulated votes during view changes.
        use crate::vote_set::VoteSet;

        let (mut state, keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 5u64;

        // Create block headers at different rounds
        let header_round1 = BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(2), // (5 + 1) % 4 = 2
            timestamp: 100_000,
            round: 1,
            is_fallback: true,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        let block_hash_r1 = header_round1.hash();

        let header_round2 = BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(3), // (5 + 2) % 4 = 3
            timestamp: 100_001,
            round: 2,
            is_fallback: true,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        let block_hash_r2 = header_round2.hash();

        let header_round3 = BlockHeader {
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0), // (5 + 3) % 4 = 0
            timestamp: 100_002,
            round: 3,
            is_fallback: true,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        let block_hash_r3 = header_round3.hash();

        // Different height - should be preserved
        let header_height6 = BlockHeader {
            height: BlockHeight(6),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(2), // (6 + 0) % 4 = 2
            timestamp: 100_003,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };
        let block_hash_h6 = header_height6.hash();

        // Create vote sets with accumulated verified votes
        let mut vote_set_r1 = VoteSet::new(Some(header_round1), 4);
        vote_set_r1.add_verified_vote(
            0,
            BlockVote {
                block_hash: block_hash_r1,
                height: BlockHeight(height),
                round: 1,
                voter: ValidatorId(0),
                signature: keys[0].sign_v1(block_hash_r1.as_bytes()),
                timestamp: 100_000,
            },
            1,
        );
        state.vote_sets.insert(block_hash_r1, vote_set_r1);

        let mut vote_set_r2 = VoteSet::new(Some(header_round2), 4);
        vote_set_r2.add_verified_vote(
            1,
            BlockVote {
                block_hash: block_hash_r2,
                height: BlockHeight(height),
                round: 2,
                voter: ValidatorId(1),
                signature: keys[1].sign_v1(block_hash_r2.as_bytes()),
                timestamp: 100_001,
            },
            1,
        );
        state.vote_sets.insert(block_hash_r2, vote_set_r2);

        let mut vote_set_r3 = VoteSet::new(Some(header_round3), 4);
        vote_set_r3.add_verified_vote(
            2,
            BlockVote {
                block_hash: block_hash_r3,
                height: BlockHeight(height),
                round: 3,
                voter: ValidatorId(2),
                signature: keys[2].sign_v1(block_hash_r3.as_bytes()),
                timestamp: 100_002,
            },
            1,
        );
        state.vote_sets.insert(block_hash_r3, vote_set_r3);

        let mut vote_set_h6 = VoteSet::new(Some(header_height6), 4);
        vote_set_h6.add_verified_vote(
            3,
            BlockVote {
                block_hash: block_hash_h6,
                height: BlockHeight(6),
                round: 0,
                voter: ValidatorId(3),
                signature: keys[3].sign_v1(block_hash_h6.as_bytes()),
                timestamp: 100_003,
            },
            1,
        );
        state.vote_sets.insert(block_hash_h6, vote_set_h6);

        assert_eq!(state.vote_sets.len(), 4);

        // Clear tracking for height 5, advancing to round 2
        state.clear_vote_tracking_for_height(height, 2);

        // Round 1 vote set should be cleared (round < new_round)
        assert!(
            !state.vote_sets.contains_key(&block_hash_r1),
            "Round 1 vote set should be cleared"
        );

        // Round 2 vote set should be preserved (round >= new_round)
        assert!(
            state.vote_sets.contains_key(&block_hash_r2),
            "Round 2 vote set should be preserved"
        );
        assert_eq!(
            state
                .vote_sets
                .get(&block_hash_r2)
                .unwrap()
                .verified_power(),
            1,
            "Round 2 vote set should still have its votes"
        );

        // Round 3 vote set should be preserved (round >= new_round)
        assert!(
            state.vote_sets.contains_key(&block_hash_r3),
            "Round 3 vote set should be preserved"
        );

        // Different height vote set should be preserved
        assert!(
            state.vote_sets.contains_key(&block_hash_h6),
            "Different height vote set should be preserved"
        );

        assert_eq!(
            state.vote_sets.len(),
            3,
            "Should have 3 remaining vote sets"
        );
    }

    #[test]
    fn test_qc_formed_does_not_propose_empty_block() {
        // When a QC forms and there's no content (empty mempool, no deferrals,
        // no aborts, no certificates), we should NOT immediately propose.
        // This avoids wasting resources on empty block pipelining.
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        // Create a QC at height 3 (so next height would be 4, which validator 0 proposes)
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        // Call on_qc_formed with empty content
        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &ReadyTransactions::default(), // empty mempool
            vec![],                        // no deferrals
            vec![],                        // no aborts
            vec![],                        // no certificates
            HashMap::new(),                // no commitment proofs
        );

        // Should NOT contain a BlockHeader broadcast (no proposal)
        let has_block_header = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastBlockHeader { .. }));

        assert!(
            !has_block_header,
            "Should not propose empty block immediately after QC formation"
        );
    }

    #[test]
    fn test_qc_formed_proposes_when_has_deferrals() {
        // When a QC forms and there IS content (e.g., deferrals), we SHOULD
        // immediately propose to pipeline block production.
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        // Create a QC at height 3 (so next height would be 4, which validator 0 proposes)
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        // Create a deferral to include
        let deferral = make_test_deferral(
            Hash::from_bytes(b"deferred_tx"),
            Hash::from_bytes(b"winner_tx"),
        );

        // Call on_qc_formed with a deferral
        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &ReadyTransactions::default(), // empty mempool
            vec![deferral],                // has a deferral
            vec![],                        // no aborts
            vec![],                        // no certificates
            HashMap::new(),                // no commitment proofs
        );

        // Should contain a BuildProposal action (proposal triggered)
        // After the refactor, proposal building is async - we emit BuildProposal
        // and the runner calls back with ProposalBuilt which triggers the broadcast.
        let has_build_proposal = actions.iter().any(
            |a| matches!(a, Action::BuildProposal { height, .. } if *height == BlockHeight(4)),
        );

        assert!(
            has_build_proposal,
            "Should trigger proposal build after QC formation when has deferrals"
        );
    }

    #[test]
    fn test_qc_verification_caching_skips_redundant_verification() {
        // Test that when we see the same QC in multiple block headers (e.g., during
        // view changes), we only verify it once and skip re-verification for subsequent blocks.
        use hyperscale_core::Action;
        use hyperscale_types::SignerBitfield;

        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));
        let mut state = BftState::new(
            1,
            {
                let key_bytes = keys[0].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));

        // Set committed_height to 1 so we don't trigger sync
        let parent_hash = Hash::from_bytes(b"parent_block");
        state.committed_height = 1;
        state.committed_hash = parent_hash;

        // Create a parent QC that will be shared by multiple blocks
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);

        let parent_qc = QuorumCertificate {
            block_hash: parent_hash,
            height: BlockHeight(1),
            parent_block_hash: Hash::ZERO,
            round: 0,
            aggregated_signature: zero_bls_signature(),
            signers: signers.clone(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 99_000,
        };

        // First block at height 2, round 0
        let header1 = BlockHeader {
            height: BlockHeight(2),
            parent_hash,
            parent_qc: parent_qc.clone(),
            proposer: ValidatorId(2), // height 2, round 0 -> validator 2
            timestamp: 100_000,
            round: 0,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        // Process first block header
        let actions1 = state.on_block_header(
            header1,
            vec![], // retry_hashes
            vec![], // priority_hashes
            vec![], // tx_hashes
            vec![], // cert_hashes
            vec![], // deferred
            vec![], // aborted
            HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );

        // Should emit VerifyQcSignature for the first block
        let has_verify_qc1 = actions1
            .iter()
            .any(|a| matches!(a, Action::VerifyQcSignature { .. }));
        assert!(has_verify_qc1, "First block should trigger QC verification");

        // Simulate QC verification success by directly inserting into the cache.
        // In real operation, this happens in on_qc_signature_verified when valid=true.
        state.verified_qcs.insert(parent_hash, 1);

        // Second block at height 2, round 1 (same parent QC - view change scenario)
        let header2 = BlockHeader {
            height: BlockHeight(2),
            parent_hash,
            parent_qc: parent_qc.clone(),
            proposer: ValidatorId(3), // height 2, round 1 -> validator 3
            timestamp: 100_001,
            round: 1,
            is_fallback: false,
            state_root: Hash::ZERO,
            state_version: 0,
            transaction_root: Hash::ZERO,
        };

        // Process second block header
        let actions2 = state.on_block_header(
            header2,
            vec![], // retry_hashes
            vec![], // priority_hashes
            vec![], // tx_hashes
            vec![], // cert_hashes
            vec![], // deferred
            vec![], // aborted
            HashMap::new(),
            &HashMap::new(),
            &HashMap::new(),
        );

        // Should NOT emit VerifyQcSignature since QC is already verified
        let has_verify_qc2 = actions2
            .iter()
            .any(|a| matches!(a, Action::VerifyQcSignature { .. }));
        assert!(
            !has_verify_qc2,
            "Second block with same parent QC should skip verification"
        );

        // Should emit vote-related actions instead (PersistAndBroadcastVote)
        let has_vote = actions2
            .iter()
            .any(|a| matches!(a, Action::PersistAndBroadcastVote { .. }));
        assert!(
            has_vote,
            "Should proceed directly to voting when QC already verified"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Transaction Ordering Validation Tests
    // ═══════════════════════════════════════════════════════════════════════════

    fn make_test_block_with_transactions(
        height: u64,
        transactions: Vec<Arc<hyperscale_types::RoutableTransaction>>,
    ) -> Block {
        Block {
            header: make_header_at_height(height, 100_000),
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions,
            certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        }
    }

    /// Create a sectioned test block with transactions properly classified into sections.
    fn make_sectioned_test_block(
        height: u64,
        retry_transactions: Vec<Arc<hyperscale_types::RoutableTransaction>>,
        priority_transactions: Vec<Arc<hyperscale_types::RoutableTransaction>>,
        transactions: Vec<Arc<hyperscale_types::RoutableTransaction>>,
        commitment_proofs: HashMap<Hash, CommitmentProof>,
    ) -> Block {
        Block {
            header: make_header_at_height(height, 100_000),
            retry_transactions,
            priority_transactions,
            transactions,
            certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs,
        }
    }

    #[allow(dead_code)]
    fn make_test_block_with_proofs(
        height: u64,
        transactions: Vec<Arc<hyperscale_types::RoutableTransaction>>,
        commitment_proofs: HashMap<Hash, CommitmentProof>,
    ) -> Block {
        Block {
            header: make_header_at_height(height, 100_000),
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions,
            certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs,
        }
    }

    /// Create a test transaction and optionally a commitment proof for it.
    /// Returns (transaction, Option<CommitmentProof>).
    fn make_test_tx_with_proof(
        seed: u8,
        with_proof: bool,
    ) -> (
        Arc<hyperscale_types::RoutableTransaction>,
        Option<CommitmentProof>,
    ) {
        use hyperscale_types::{test_utils, ShardGroupId, StateEntry};

        let tx = test_utils::test_transaction(seed);
        let tx_arc = Arc::new(tx);

        let proof = if with_proof {
            let node = test_utils::test_node(seed);
            Some(CommitmentProof::new(
                tx_arc.hash(),
                ShardGroupId(1),
                SignerBitfield::new(4),
                zero_bls_signature(),
                BlockHeight(1),
                1000, // block_timestamp
                vec![StateEntry::test_entry(node, 0, vec![], None)],
            ))
        } else {
            None
        };

        (tx_arc, proof)
    }

    fn make_test_tx(seed: u8, _with_proof: bool) -> Arc<hyperscale_types::RoutableTransaction> {
        use hyperscale_types::test_utils;
        Arc::new(test_utils::test_transaction(seed))
    }

    /// Create a retry transaction for testing.
    fn make_retry_tx(seed: u8) -> Arc<hyperscale_types::RoutableTransaction> {
        use hyperscale_types::test_utils;
        let original = test_utils::test_transaction(seed);
        let winner_hash = Hash::from_bytes(&[seed.wrapping_add(100); 32]);
        Arc::new(original.create_retry(winner_hash, BlockHeight(1)))
    }

    /// Sort transactions by hash for test setup
    fn sort_txs_by_hash(txs: &mut [Arc<hyperscale_types::RoutableTransaction>]) {
        txs.sort_by_key(|tx| tx.hash());
    }

    #[test]
    fn test_validate_transaction_ordering_empty_block() {
        let state = make_test_state();
        let block = make_test_block_with_transactions(5, vec![]);
        assert!(state.validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn test_validate_transaction_ordering_single_tx() {
        let state = make_test_state();
        let tx = make_test_tx(1, false);
        let block = make_test_block_with_transactions(5, vec![tx]);
        assert!(state.validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn test_validate_transaction_ordering_valid_no_proofs() {
        let state = make_test_state();

        // Create TXs and sort by hash
        let mut txs = vec![
            make_test_tx(10, false),
            make_test_tx(20, false),
            make_test_tx(30, false),
        ];
        sort_txs_by_hash(&mut txs);

        let block = make_test_block_with_transactions(5, txs);
        assert!(state.validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn test_validate_transaction_ordering_invalid_no_proofs() {
        let state = make_test_state();

        // Create TXs, sort, then reverse (invalid order)
        let mut txs = vec![
            make_test_tx(10, false),
            make_test_tx(20, false),
            make_test_tx(30, false),
        ];
        sort_txs_by_hash(&mut txs);
        txs.reverse();

        let block = make_test_block_with_transactions(5, txs);
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in hash order"));
    }

    #[test]
    fn test_validate_transaction_ordering_valid_with_proofs_first() {
        let state = make_test_state();

        // Create TXs for priority group and non-priority group
        let (tx1, proof1) = make_test_tx_with_proof(10, true);
        let (tx2, proof2) = make_test_tx_with_proof(20, true);
        let (tx3, _) = make_test_tx_with_proof(30, false);
        let (tx4, _) = make_test_tx_with_proof(40, false);

        // Sort each group
        let mut priority_txs = vec![tx1.clone(), tx2.clone()];
        sort_txs_by_hash(&mut priority_txs);

        let mut other_txs = vec![tx3, tx4];
        sort_txs_by_hash(&mut other_txs);

        // Build proofs map for the block
        let mut proofs = HashMap::new();
        proofs.insert(tx1.hash(), proof1.unwrap());
        proofs.insert(tx2.hash(), proof2.unwrap());

        // Use sectioned block with priority TXs in priority section
        let block = make_sectioned_test_block(5, vec![], priority_txs, other_txs, proofs);
        assert!(state.validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn test_validate_transaction_ordering_invalid_proof_group_unsorted() {
        let state = make_test_state();

        // Create priority TXs with proofs
        let (tx1, proof1) = make_test_tx_with_proof(10, true);
        let (tx2, proof2) = make_test_tx_with_proof(20, true);

        // Sort, then reverse (invalid order within priority section)
        let mut priority_txs = vec![tx1.clone(), tx2.clone()];
        sort_txs_by_hash(&mut priority_txs);
        priority_txs.reverse();

        // Build proofs map
        let mut proofs = HashMap::new();
        proofs.insert(tx1.hash(), proof1.unwrap());
        proofs.insert(tx2.hash(), proof2.unwrap());

        let block = make_sectioned_test_block(5, vec![], priority_txs, vec![], proofs);
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("priority section not in hash order"));
    }

    #[test]
    fn test_validate_transaction_ordering_invalid_non_priority_before_priority() {
        let state = make_test_state();

        // Non-priority TX in priority section without proof - invalid
        let (no_proof_tx, _) = make_test_tx_with_proof(10, false);
        let (proof_tx, proof) = make_test_tx_with_proof(20, true);

        // Build proofs map (only proof_tx has a proof)
        let mut proofs = HashMap::new();
        proofs.insert(proof_tx.hash(), proof.unwrap());

        // Put no_proof_tx in priority section (invalid - has no proof)
        let block = make_sectioned_test_block(5, vec![], vec![no_proof_tx], vec![proof_tx], proofs);
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no commitment proof"));
    }

    #[test]
    fn test_validate_transaction_ordering_all_have_proofs() {
        let state = make_test_state();

        // All TXs have proofs - valid as long as sorted, all in priority section
        let (tx1, proof1) = make_test_tx_with_proof(10, true);
        let (tx2, proof2) = make_test_tx_with_proof(20, true);
        let (tx3, proof3) = make_test_tx_with_proof(30, true);

        let mut priority_txs = vec![tx1.clone(), tx2.clone(), tx3.clone()];
        sort_txs_by_hash(&mut priority_txs);

        // Build proofs map
        let mut proofs = HashMap::new();
        proofs.insert(tx1.hash(), proof1.unwrap());
        proofs.insert(tx2.hash(), proof2.unwrap());
        proofs.insert(tx3.hash(), proof3.unwrap());

        let block = make_sectioned_test_block(5, vec![], priority_txs, vec![], proofs);
        assert!(state.validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn test_validate_transaction_ordering_retries_first() {
        let state = make_test_state();

        // Create retry TXs, proof TXs, and regular TXs
        let retry1 = make_retry_tx(10);
        let retry2 = make_retry_tx(20);
        let (proof_tx, proof) = make_test_tx_with_proof(30, true);
        let regular = make_test_tx(40, false);

        // Sort each tier by hash
        let mut retries = vec![retry1.clone(), retry2.clone()];
        sort_txs_by_hash(&mut retries);

        let priority_txs = vec![proof_tx.clone()];

        let others = vec![regular.clone()];

        let mut proofs_map = HashMap::new();
        proofs_map.insert(proof_tx.hash(), proof.unwrap());

        // Use sectioned block: retries in retry section, proof TX in priority, regular in others
        let block = make_sectioned_test_block(5, retries, priority_txs, others, proofs_map);
        assert!(state.validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn test_validate_transaction_ordering_invalid_retry_after_proof() {
        let state = make_test_state();

        // Create a retry and a proof TX
        let retry = make_retry_tx(10);
        let (proof_tx, proof) = make_test_tx_with_proof(30, true);

        let mut proofs_map = HashMap::new();
        proofs_map.insert(proof_tx.hash(), proof.unwrap());

        // Invalid: put retry in priority section (it's not a non-retry TX with proof)
        let block = make_sectioned_test_block(5, vec![], vec![retry], vec![], proofs_map);
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("Retry transaction"),
            "Should detect retry in priority section"
        );
    }

    #[test]
    fn test_validate_transaction_ordering_invalid_retry_after_other() {
        let state = make_test_state();

        // Create a retry and a regular TX
        let retry = make_retry_tx(10);

        // Invalid: put retry in other section (should be in retry section)
        let block = make_sectioned_test_block(5, vec![], vec![], vec![retry], HashMap::new());
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("Retry transaction"),
            "Should detect retry in other section"
        );
    }

    #[test]
    fn test_validate_transaction_ordering_retries_only() {
        let state = make_test_state();

        // All retries in retry section - valid as long as sorted
        let mut retries = vec![make_retry_tx(10), make_retry_tx(20), make_retry_tx(30)];
        sort_txs_by_hash(&mut retries);

        let block = make_sectioned_test_block(5, retries, vec![], vec![], HashMap::new());
        assert!(state.validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn test_validate_transaction_ordering_retries_unsorted() {
        let state = make_test_state();

        // Retries not sorted by hash in retry section
        let mut retries = vec![make_retry_tx(10), make_retry_tx(20), make_retry_tx(30)];
        sort_txs_by_hash(&mut retries);
        retries.reverse(); // Make invalid

        let block = make_sectioned_test_block(5, retries, vec![], vec![], HashMap::new());
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("retry section not in hash order"));
    }

    #[test]
    fn test_min_block_interval_rate_limits_immediate_proposal() {
        // When a QC forms with content but we proposed too recently,
        // the immediate proposal should be rate-limited.

        let mut state = make_test_state();

        // Set current time and simulate that we just proposed
        state.set_time(Duration::from_millis(1000));
        state.last_proposal_time = Duration::from_millis(950); // 50ms ago

        // min_block_interval is 150ms by default, so we're within the rate limit window

        // Create a QC at height 3 (so next height would be 4, which validator 0 proposes)
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        };

        // Create a deferral so there's content to propose
        let deferral = make_test_deferral(
            Hash::from_bytes(b"deferred_tx"),
            Hash::from_bytes(b"winner_tx"),
        );

        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &ReadyTransactions::default(), // empty mempool
            vec![deferral],                // has content
            vec![],
            vec![],
            HashMap::new(),
        );

        // Should NOT contain a BlockHeader broadcast (rate limited)
        let has_block_header = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastBlockHeader { .. }));

        assert!(
            !has_block_header,
            "Should NOT propose immediately when rate limited (proposed 50ms ago, limit is 150ms)"
        );
    }

    #[test]
    fn test_min_block_interval_allows_proposal_after_interval() {
        // When enough time has passed since the last proposal,
        // immediate proposals should be allowed.

        let mut state = make_test_state();

        // Set current time and simulate that we proposed long enough ago
        state.set_time(Duration::from_millis(1000));
        state.last_proposal_time = Duration::from_millis(800); // 200ms ago

        // min_block_interval is 150ms by default, so 200ms > 150ms - should be allowed

        // Create a QC at height 3 (so next height would be 4, which validator 0 proposes)
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        };

        // Create a deferral so there's content to propose
        let deferral = make_test_deferral(
            Hash::from_bytes(b"deferred_tx"),
            Hash::from_bytes(b"winner_tx"),
        );

        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &ReadyTransactions::default(), // empty mempool
            vec![deferral],                // has content
            vec![],
            vec![],
            HashMap::new(),
        );

        // Should contain a BuildProposal action (enough time passed)
        // After the refactor, proposal building is async - we emit BuildProposal
        // and the runner calls back with ProposalBuilt which triggers the broadcast.
        let has_build_proposal = actions.iter().any(
            |a| matches!(a, Action::BuildProposal { height, .. } if *height == BlockHeight(4)),
        );

        assert!(
            has_build_proposal,
            "Should propose after rate limit interval has passed (200ms > 150ms)"
        );
    }

    #[test]
    fn test_min_block_interval_configurable() {
        // Test that the min_block_interval config is respected.

        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));

        // Create config with longer min_block_interval
        let config = BftConfig {
            min_block_interval: Duration::from_millis(500),
            ..BftConfig::default()
        };

        let mut state = BftState::new(
            0,
            {
                let key_bytes = keys[0].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            config,
            RecoveredState::default(),
        );

        // Set current time and simulate that we proposed 200ms ago
        state.set_time(Duration::from_millis(1000));
        state.last_proposal_time = Duration::from_millis(800); // 200ms ago

        // With min_block_interval of 500ms, 200ms is not enough - should be rate limited

        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        };

        let deferral = make_test_deferral(
            Hash::from_bytes(b"deferred_tx"),
            Hash::from_bytes(b"winner_tx"),
        );

        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &ReadyTransactions::default(),
            vec![deferral],
            vec![],
            vec![],
            HashMap::new(),
        );

        let has_block_header = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastBlockHeader { .. }));

        assert!(
            !has_block_header,
            "Should be rate limited with custom 500ms interval (only 200ms passed)"
        );
    }

    #[test]
    fn test_min_block_interval_zero_disables_rate_limiting() {
        // Test that setting min_block_interval to zero disables rate limiting.

        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));

        // Create config with zero min_block_interval (disabled)
        let config = BftConfig {
            min_block_interval: Duration::ZERO,
            ..BftConfig::default()
        };

        let mut state = BftState::new(
            0,
            {
                let key_bytes = keys[0].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            config,
            RecoveredState::default(),
        );

        // Propose just now (0ms ago) - normally would be rate limited
        state.set_time(Duration::from_millis(1000));
        state.last_proposal_time = Duration::from_millis(1000);

        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        };

        let deferral = make_test_deferral(
            Hash::from_bytes(b"deferred_tx"),
            Hash::from_bytes(b"winner_tx"),
        );

        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &ReadyTransactions::default(),
            vec![deferral],
            vec![],
            vec![],
            HashMap::new(),
        );

        // Should contain a BuildProposal action (rate limiting disabled)
        // After the refactor, proposal building is async - we emit BuildProposal
        // and the runner calls back with ProposalBuilt which triggers the broadcast.
        let has_build_proposal = actions.iter().any(
            |a| matches!(a, Action::BuildProposal { height, .. } if *height == BlockHeight(4)),
        );

        assert!(
            has_build_proposal,
            "Should allow immediate proposal when min_block_interval is zero"
        );
    }

    #[test]
    fn test_proposal_timer_updates_last_proposal_time() {
        // Verify that on_proposal_built updates last_proposal_time when a proposal is broadcast.
        // After the refactor, on_proposal_timer emits BuildProposal, and the runner calls back
        // with on_proposal_built which updates last_proposal_time and broadcasts the block.
        let mut state = make_test_state();
        state.set_time(Duration::from_millis(5000));

        // Ensure last_proposal_time starts at zero
        assert_eq!(state.last_proposal_time, Duration::ZERO);

        // Proposer rotation is (height + round) % committee_size.
        // With 4 validators, validator 0 proposes for height 0, 4, 8, etc.
        // Since committed_height=0, next height is 1, and (1+0)%4=1, so validator 1 proposes.
        // We need to set up a QC so that the next height is 4 (validator 0's turn).
        let parent_qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 5000,
        };
        state.latest_qc = Some(parent_qc.clone());

        // Now next_height = 4, (4+0)%4=0, so validator 0 proposes
        let actions = state.on_proposal_timer(
            &ReadyTransactions::default(),
            vec![],
            vec![],
            vec![],
            HashMap::new(),
        );

        // Check that a BuildProposal action was emitted (async proposal)
        let build_proposal = actions.iter().any(
            |a| matches!(a, Action::BuildProposal { height, .. } if *height == BlockHeight(4)),
        );

        assert!(
            build_proposal,
            "Validator 0 should request proposal build for height 4"
        );

        // last_proposal_time not yet updated - happens on_proposal_built
        assert_eq!(state.last_proposal_time, Duration::ZERO);

        // Simulate the runner completing the proposal build
        let block = Block {
            header: BlockHeader {
                height: BlockHeight(4),
                parent_hash: Hash::from_bytes(b"block_3"),
                parent_qc,
                proposer: ValidatorId(0),
                timestamp: 5000,
                round: 0,
                is_fallback: false,
                state_root: Hash::ZERO,
                state_version: 0,
                transaction_root: Hash::ZERO,
            },
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        };
        let block_hash = block.hash();
        let block_arc = Arc::new(block);

        let broadcast_actions = state.on_proposal_built(BlockHeight(4), 0, block_arc, block_hash);

        // Check that a BlockHeader broadcast was emitted
        let has_broadcast = broadcast_actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastBlockHeader { .. }));
        assert!(
            has_broadcast,
            "Should broadcast block after on_proposal_built"
        );

        // Verify last_proposal_time was updated
        assert_eq!(
            state.last_proposal_time,
            Duration::from_millis(5000),
            "last_proposal_time should be updated to current time"
        );
    }

    // ========================================================================
    // Crypto Verification Tests - Using real BLS signatures
    // ========================================================================

    #[test]
    fn test_qc_with_real_bls_signatures() {
        use hyperscale_test_helpers::{fixtures, TestCommittee};

        let committee = TestCommittee::new(4, 42);
        let parent_hash = Hash::from_bytes(b"parent_block");

        // Create a QC with REAL aggregated BLS signatures
        let qc = fixtures::make_signed_qc(
            &committee,
            &[0, 1, 2], // 3 voters for quorum
            parent_hash,
            BlockHeight(1),
            0,
            Hash::ZERO,
            ShardGroupId(0),
        );

        // Build the signing message as the runner would
        let signing_message = hyperscale_types::block_vote_message(
            ShardGroupId(0),
            qc.height.0,
            qc.round,
            &qc.block_hash,
        );

        // Get signer public keys based on bitfield
        let signer_keys: Vec<_> = qc
            .signers
            .set_indices()
            .map(|idx| *committee.public_key(idx))
            .collect();

        // Aggregate public keys (what the runner does)
        let aggregated_pk =
            Bls12381G1PublicKey::aggregate(&signer_keys, true).expect("Aggregation should succeed");

        // Verify the QC signature - THIS IS THE CRITICAL TEST
        let valid = verify_bls12381_v1(&signing_message, &aggregated_pk, &qc.aggregated_signature);
        assert!(
            valid,
            "QC signature should verify successfully with real BLS signatures"
        );

        // Also verify that batch verification works
        let signatures: Vec<_> = (0..3)
            .map(|i| committee.keypair(i).sign_v1(&signing_message))
            .collect();
        let pubkeys: Vec<_> = (0..3).map(|i| *committee.public_key(i)).collect();

        let batch_valid = batch_verify_bls_same_message(&signing_message, &signatures, &pubkeys);
        assert!(batch_valid, "Batch verification should also succeed");
    }

    #[test]
    fn test_block_vote_with_real_bls_signature() {
        use hyperscale_test_helpers::{fixtures, TestCommittee};

        let committee = TestCommittee::new(4, 42);
        let block_hash = Hash::from_bytes(b"test_block");
        let shard = ShardGroupId(0);

        // Create a properly signed block vote
        let vote = fixtures::make_signed_block_vote(
            &committee,
            0, // voter index
            block_hash,
            BlockHeight(1),
            0,
            shard,
        );

        // Verify the signature manually
        let message = hyperscale_types::block_vote_message(shard, 1, 0, &block_hash);
        let valid = verify_bls12381_v1(&message, committee.public_key(0), &vote.signature);
        assert!(valid, "Block vote signature should verify");

        // Verify with wrong key fails
        let invalid = verify_bls12381_v1(&message, committee.public_key(1), &vote.signature);
        assert!(!invalid, "Block vote should NOT verify with wrong key");
    }

    #[test]
    fn test_batch_verify_block_votes_same_message() {
        use hyperscale_test_helpers::TestCommittee;

        let committee = TestCommittee::new(4, 42);
        let block_hash = Hash::from_bytes(b"test_block");
        let shard = ShardGroupId(0);
        let height = 1u64;
        let round = 0u64;

        // All validators sign the same message
        let message = hyperscale_types::block_vote_message(shard, height, round, &block_hash);

        let signatures: Vec<Bls12381G2Signature> = (0..3)
            .map(|i| committee.keypair(i).sign_v1(&message))
            .collect();

        let pubkeys: Vec<Bls12381G1PublicKey> = (0..3).map(|i| *committee.public_key(i)).collect();

        // Batch verify all signatures at once (same message optimization)
        let valid = batch_verify_bls_same_message(&message, &signatures, &pubkeys);
        assert!(
            valid,
            "Batch verification should succeed for valid signatures"
        );
    }

    #[test]
    fn test_batch_verify_rejects_one_bad_signature() {
        use hyperscale_test_helpers::TestCommittee;

        let committee = TestCommittee::new(4, 42);
        let block_hash = Hash::from_bytes(b"test_block");
        let shard = ShardGroupId(0);
        let height = 1u64;
        let round = 0u64;

        let message = hyperscale_types::block_vote_message(shard, height, round, &block_hash);

        // First two are valid, third is signed with wrong key
        let signatures: Vec<Bls12381G2Signature> = vec![
            committee.keypair(0).sign_v1(&message),
            committee.keypair(1).sign_v1(&message),
            committee.keypair(3).sign_v1(&message), // Wrong key! (claims to be validator 2)
        ];

        let pubkeys: Vec<Bls12381G1PublicKey> = vec![
            *committee.public_key(0),
            *committee.public_key(1),
            *committee.public_key(2), // But we're verifying with key 2
        ];

        // Batch verification should fail
        let valid = batch_verify_bls_same_message(&message, &signatures, &pubkeys);
        assert!(
            !valid,
            "Batch verification should fail when one signature is invalid"
        );
    }

    #[test]
    fn test_qc_aggregation_and_verification() {
        use hyperscale_test_helpers::TestCommittee;

        let committee = TestCommittee::new(4, 42);
        let block_hash = Hash::from_bytes(b"test_block");
        let shard = ShardGroupId(0);
        let height = 1u64;
        let round = 0u64;

        let message = hyperscale_types::block_vote_message(shard, height, round, &block_hash);

        // Simulate vote collection and aggregation (what vote_set.rs does)
        let voter_indices = [0, 1, 2];

        let signatures: Vec<Bls12381G2Signature> = voter_indices
            .iter()
            .map(|&i| committee.keypair(i).sign_v1(&message))
            .collect();

        // Aggregate signatures (what happens when building QC)
        let aggregated_sig =
            Bls12381G2Signature::aggregate(&signatures, true).expect("Aggregation should succeed");

        // Aggregate public keys of signers
        let signer_pks: Vec<Bls12381G1PublicKey> = voter_indices
            .iter()
            .map(|&i| *committee.public_key(i))
            .collect();
        let aggregated_pk = Bls12381G1PublicKey::aggregate(&signer_pks, true)
            .expect("PK aggregation should succeed");

        // Verify aggregated signature against aggregated public key
        let valid = verify_bls12381_v1(&message, &aggregated_pk, &aggregated_sig);
        assert!(valid, "Aggregated QC signature should verify");
    }

    // ========================================================================
    // Sync Block Proposal Tests
    // ========================================================================

    #[test]
    fn test_syncing_validator_proposes_empty_block() {
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        // Set up a QC so we propose for height 4 (validator 0's turn: (4+0)%4=0)
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };
        state.latest_qc = Some(qc);

        // Enter sync mode
        assert!(!state.is_syncing());
        state.set_syncing(true);
        assert!(state.is_syncing());

        // Trigger proposal timer with transactions (which should be ignored)
        let ready_txs = ReadyTransactions {
            retries: vec![],
            priority: vec![],
            others: vec![Arc::new(hyperscale_types::test_utils::test_transaction(1))],
        };

        let actions = state.on_proposal_timer(&ready_txs, vec![], vec![], vec![], HashMap::new());

        // Should have broadcast a block header
        let has_block_header = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastBlockHeader { .. }));
        assert!(
            has_block_header,
            "Should broadcast a block header while syncing"
        );

        // Verify the block is empty (sync block)
        let block_gossip = actions.iter().find_map(|a| {
            if let Action::BroadcastBlockHeader { header: gossip, .. } = a {
                Some(gossip)
            } else {
                None
            }
        });

        let gossip = block_gossip.expect("Should have block header gossip");
        assert!(
            gossip.transaction_hashes.is_empty(),
            "Sync block should have no transactions"
        );
        assert!(
            gossip.retry_hashes.is_empty(),
            "Sync block should have no retry transactions"
        );
        assert!(
            gossip.priority_hashes.is_empty(),
            "Sync block should have no priority transactions"
        );
        assert!(
            gossip.certificate_hashes.is_empty(),
            "Sync block should have no certificates"
        );

        // Verify is_fallback is false (sync blocks are not fallback blocks)
        assert!(
            !gossip.header.is_fallback,
            "Sync block should not be marked as fallback"
        );
    }

    #[test]
    fn test_syncing_validator_uses_current_timestamp() {
        let mut state = make_test_state();
        let current_time = Duration::from_secs(12345);
        state.set_time(current_time);

        // Set up QC with old timestamp
        let old_timestamp = 1000u64;
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: old_timestamp,
        };
        state.latest_qc = Some(qc);

        // Enter sync mode
        state.set_syncing(true);

        let actions = state.on_proposal_timer(
            &ReadyTransactions::default(),
            vec![],
            vec![],
            vec![],
            HashMap::new(),
        );

        // Extract the block header
        let gossip = actions.iter().find_map(|a| {
            if let Action::BroadcastBlockHeader { header: gossip, .. } = a {
                Some(gossip)
            } else {
                None
            }
        });

        let gossip = gossip.expect("Should have block header");

        // Sync blocks use current time, NOT inherited timestamp
        assert_eq!(
            gossip.header.timestamp,
            current_time.as_millis() as u64,
            "Sync block should use current timestamp, not parent's"
        );
        assert_ne!(
            gossip.header.timestamp, old_timestamp,
            "Sync block should NOT inherit parent timestamp like fallback blocks"
        );
    }

    #[test]
    fn test_sync_complete_exits_sync_mode() {
        let mut state = make_test_state();

        // Enter sync mode
        state.set_syncing(true);
        assert!(state.is_syncing());

        // Exit sync mode
        let actions = state.on_sync_complete();
        assert!(!state.is_syncing());

        // May return fetch actions for pending blocks (or empty if no pending blocks)
        // The main assertion is that syncing is now false
        // In this test state there are no pending blocks, so actions should be empty
        assert!(
            actions.is_empty(),
            "Fresh test state has no pending blocks, so no fetch actions expected"
        );
    }

    #[test]
    fn test_syncing_validator_can_vote_for_others_blocks() {
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        // Enter sync mode
        state.set_syncing(true);

        // Create a block from another proposer (validator 1 proposes height 1)
        let block_hash = Hash::from_bytes(b"other_proposer_block");
        let height = 1u64;
        let round = 0u64;

        // Directly call try_vote_on_block (simulating after QC verification)
        let actions = state.try_vote_on_block(block_hash, height, round);

        // Should have created a vote
        let has_vote = actions
            .iter()
            .any(|a| matches!(a, Action::PersistAndBroadcastVote { .. }));
        assert!(
            has_vote,
            "Syncing validator should still be able to vote for others' blocks"
        );

        // Verify vote is recorded
        assert!(
            state.voted_heights.contains_key(&height),
            "Vote should be recorded in voted_heights"
        );
    }

    #[test]
    fn test_view_changes_allowed_during_sync() {
        let mut state = make_test_state();

        // Set up time so that view change would trigger
        state.set_time(Duration::from_secs(100));
        state.last_leader_activity = Duration::from_secs(0); // Very old

        // Without sync mode, should want to advance round
        assert!(
            state.should_advance_round(),
            "Should want to advance round when not syncing"
        );

        // Enter sync mode
        state.set_syncing(true);

        // Syncing nodes SHOULD still participate in view changes.
        // They receive headers at the current height/round and need to help
        // advance the view if the leader fails. When selected as proposer
        // after a view change, they propose an empty sync block.
        assert!(
            state.should_advance_round(),
            "Should still advance round while syncing - syncing nodes participate in consensus"
        );

        // Verify check_round_timeout returns actions (view change)
        let timeout_actions = state.check_round_timeout();
        assert!(
            timeout_actions.is_some(),
            "check_round_timeout should trigger view change even while syncing"
        );
    }

    #[test]
    fn test_sync_mode_resets_leader_activity_on_exit() {
        let mut state = make_test_state();

        // Set up stale leader activity
        state.set_time(Duration::from_secs(100));
        state.last_leader_activity = Duration::from_secs(0);

        // Enter and exit sync mode
        state.set_syncing(true);
        state.on_sync_complete();

        // Leader activity should be reset to current time
        assert_eq!(
            state.last_leader_activity,
            Duration::from_secs(100),
            "Leader activity should be reset when exiting sync mode"
        );
    }

    #[test]
    fn test_syncing_validator_vote_locking_preserved() {
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        // Enter sync mode
        state.set_syncing(true);

        let height = 1u64;
        let block_a = Hash::from_bytes(b"block_a");
        let block_b = Hash::from_bytes(b"block_b");

        // Vote for block A
        let actions = state.try_vote_on_block(block_a, height, 0);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::PersistAndBroadcastVote { .. })),
            "Should vote for block A"
        );

        // Try to vote for block B at same height - should be blocked
        let actions = state.try_vote_on_block(block_b, height, 1);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::PersistAndBroadcastVote { .. })),
            "Should NOT vote for block B (vote locked to A)"
        );

        // Verify still locked to A
        assert_eq!(
            state.voted_heights.get(&height).map(|(h, _)| *h),
            Some(block_a),
            "Should remain locked to block A"
        );
    }

    #[test]
    fn test_start_sync_sets_syncing_flag() {
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        assert!(!state.is_syncing(), "Should not be syncing initially");

        // Call start_sync (private, so we simulate what check_sync_health does)
        // Set up latest_qc so check_sync_health has a target
        state.latest_qc = Some(QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_5"),
            height: BlockHeight(5),
            parent_block_hash: Hash::from_bytes(b"block_4"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        });

        // check_sync_health should trigger sync since we're behind (committed=0, qc=5)
        // and gap > 3 without a pending commit
        let actions = state.check_sync_health();

        assert!(
            state.is_syncing(),
            "Should be in sync mode after check_sync_health triggers start_sync"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::StartSync { .. })),
            "Should emit StartSync action"
        );
    }

    #[test]
    fn test_stale_sync_block_ignored() {
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));
        state.committed_height = 10; // Already committed past height 1

        // Create a stale synced block at height 1
        let block = Block {
            header: BlockHeader {
                height: BlockHeight(1),
                parent_hash: Hash::ZERO,
                parent_qc: QuorumCertificate::genesis(),
                proposer: ValidatorId(1),
                timestamp: 1000,
                round: 0,
                is_fallback: false,
                state_root: Hash::ZERO,
                state_version: 0,
                transaction_root: Hash::ZERO,
            },
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        };

        let qc = QuorumCertificate {
            block_hash: block.hash(),
            height: BlockHeight(1),
            parent_block_hash: Hash::ZERO,
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        };

        // Should return empty actions since block is stale
        let actions = state.on_sync_block_ready_to_apply(block, qc);
        assert!(actions.is_empty(), "Stale sync block should be ignored");

        // Should NOT have set syncing flag
        assert!(
            !state.is_syncing(),
            "Should not enter sync mode for stale block"
        );
    }

    #[test]
    fn test_sync_block_records_leader_activity() {
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));
        state.last_leader_activity = Duration::from_secs(0);

        // Set up QC so we're the proposer for height 4
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };
        state.latest_qc = Some(qc);

        // Enter sync mode
        state.set_syncing(true);

        // Propose (which builds sync block)
        let _actions = state.on_proposal_timer(
            &ReadyTransactions::default(),
            vec![],
            vec![],
            vec![],
            HashMap::new(),
        );

        // Leader activity should be updated
        assert_eq!(
            state.last_leader_activity,
            Duration::from_secs(100),
            "Sync block proposal should record leader activity"
        );
    }

    #[test]
    fn test_sync_block_vs_fallback_block_differences() {
        // This test verifies the key differences between sync blocks and fallback blocks
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        // Set up QC with specific timestamp
        let parent_timestamp = 50_000u64;
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: parent_timestamp,
        };
        state.latest_qc = Some(qc);

        // Test 1: Build sync block
        state.set_syncing(true);
        let sync_actions = state.build_and_broadcast_sync_block(4, 0);
        state.set_syncing(false);

        // Reset state for fallback test
        state.pending_blocks.clear();
        state.pending_block_created_at.clear();
        state.certified_blocks.clear();
        state.voted_heights.clear();

        // Test 2: Build fallback block
        let fallback_actions = state.build_and_broadcast_fallback_block(4, 1);

        // Extract headers
        let sync_header = sync_actions
            .iter()
            .find_map(|a| {
                if let Action::BroadcastBlockHeader { header: gossip, .. } = a {
                    Some(&gossip.header)
                } else {
                    None
                }
            })
            .expect("Should have sync block header");

        let fallback_header = fallback_actions
            .iter()
            .find_map(|a| {
                if let Action::BroadcastBlockHeader { header: gossip, .. } = a {
                    Some(&gossip.header)
                } else {
                    None
                }
            })
            .expect("Should have fallback block header");

        // Difference 1: is_fallback flag
        assert!(
            !sync_header.is_fallback,
            "Sync block should have is_fallback=false"
        );
        assert!(
            fallback_header.is_fallback,
            "Fallback block should have is_fallback=true"
        );

        // Difference 2: timestamp handling
        assert_eq!(
            sync_header.timestamp,
            Duration::from_secs(100).as_millis() as u64,
            "Sync block uses current timestamp"
        );
        assert_eq!(
            fallback_header.timestamp, parent_timestamp,
            "Fallback block inherits parent timestamp"
        );
    }

    #[test]
    fn test_chain_advances_with_syncing_proposer() {
        // Simulate a scenario where a syncing proposer keeps the chain advancing
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        // Set up initial QC
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: zero_bls_signature(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };
        state.latest_qc = Some(qc);

        // Enter sync mode
        state.set_syncing(true);

        // Propose first sync block
        let actions1 = state.on_proposal_timer(
            &ReadyTransactions::default(),
            vec![],
            vec![],
            vec![],
            HashMap::new(),
        );

        // Verify we got a proposal (not skipped due to syncing)
        let has_proposal = actions1
            .iter()
            .any(|a| matches!(a, Action::BroadcastBlockHeader { .. }));
        assert!(
            has_proposal,
            "Syncing validator should still propose (empty blocks)"
        );

        // Verify we also voted for our own block
        let has_vote = actions1
            .iter()
            .any(|a| matches!(a, Action::PersistAndBroadcastVote { .. }));
        assert!(
            has_vote,
            "Syncing validator should vote for their own sync block"
        );
    }

    #[test]
    fn test_linear_backoff_timeout() {
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        // Default config: base = 3s, increment = 500ms
        let base_timeout = Duration::from_secs(3);
        let increment = Duration::from_millis(500);

        // At round 0 (same as view_at_height_start), timeout should be base
        assert_eq!(state.view, 0);
        assert_eq!(state.view_at_height_start, 0);
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout,
            "Round 0: timeout should equal base timeout"
        );

        // Advance round (view change)
        state.view = 1;
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout + increment,
            "Round 1: timeout should be base + 1*increment"
        );

        // Advance round again
        state.view = 2;
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout + increment * 2,
            "Round 2: timeout should be base + 2*increment"
        );

        // Advance round to 5
        state.view = 5;
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout + increment * 5,
            "Round 5: timeout should be base + 5*increment"
        );
    }

    #[test]
    fn test_linear_backoff_resets_on_height_advance() {
        let mut state = make_test_state();
        state.set_time(Duration::from_secs(100));

        let base_timeout = Duration::from_secs(3);
        let increment = Duration::from_millis(500);

        // Simulate several view changes at height 0
        state.view = 5;
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout + increment * 5,
            "After 5 view changes: timeout should include backoff"
        );

        // Simulate height advance (commit)
        // This should reset view_at_height_start to current view
        state.committed_height = 1;
        state.view_at_height_start = state.view; // This is what happens in commit

        // Now timeout should be back to base (0 rounds at new height)
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout,
            "After height advance: timeout should reset to base"
        );

        // Another view change at new height
        state.view = 6;
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout + increment,
            "After 1 view change at new height: timeout should be base + increment"
        );
    }

    #[test]
    fn test_linear_backoff_zero_increment_disables_backoff() {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));

        let config = BftConfig::default().with_view_change_timeout_increment(Duration::ZERO);

        let mut state = BftState::new(
            0,
            {
                let key_bytes = keys[0].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            config,
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));
        let base_timeout = Duration::from_secs(3);

        // With zero increment, timeout should always be base regardless of round
        assert_eq!(state.current_view_change_timeout(), base_timeout);

        state.view = 10;
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout,
            "With zero increment, timeout should remain constant"
        );

        state.view = 100;
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout,
            "Even at high round numbers, timeout should remain constant"
        );
    }

    #[test]
    fn test_linear_backoff_affects_should_advance_round() {
        let mut state = make_test_state();

        // Set up: we're at round 0, last_leader_activity = 0
        state.view = 0;
        state.view_at_height_start = 0;
        state.last_leader_activity = Duration::ZERO;

        // Base timeout is 3s
        // At exactly 3s, should trigger (rounds_at_height = 0)
        state.set_time(Duration::from_secs(3));
        assert!(
            state.should_advance_round(),
            "At base timeout, should trigger view change"
        );

        // Now at round 1, timeout should be 3.5s
        // Reset and simulate we're at round 1
        state.view = 1;
        state.last_leader_activity = Duration::from_secs(10);

        // At 3s after last activity, should NOT trigger (need 3.5s)
        state.set_time(Duration::from_secs(13));
        assert!(
            !state.should_advance_round(),
            "At round 1, 3s is not enough (need 3.5s)"
        );

        // At 3.5s after last activity, should trigger
        state.set_time(Duration::from_millis(13500));
        assert!(
            state.should_advance_round(),
            "At round 1, 3.5s should trigger view change"
        );

        // At round 5, timeout should be 5.5s
        state.view = 5;
        state.last_leader_activity = Duration::from_secs(20);

        // At 5s after last activity, should NOT trigger
        state.set_time(Duration::from_secs(25));
        assert!(
            !state.should_advance_round(),
            "At round 5, 5s is not enough (need 5.5s)"
        );

        // At 5.5s after last activity, should trigger
        state.set_time(Duration::from_millis(25500));
        assert!(
            state.should_advance_round(),
            "At round 5, 5.5s should trigger view change"
        );
    }

    #[test]
    fn test_linear_backoff_respects_max_cap() {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));

        // Configure with a 10s max cap (default is 30s)
        let config =
            BftConfig::default().with_view_change_timeout_max(Some(Duration::from_secs(10)));

        let mut state = BftState::new(
            0,
            {
                let key_bytes = keys[0].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            config,
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));

        let base_timeout = Duration::from_secs(3);
        let increment = Duration::from_millis(500);
        let max_timeout = Duration::from_secs(10);

        // At low rounds, timeout follows linear formula
        state.view = 5;
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout + increment * 5,
            "At round 5: should be 5.5s (below cap)"
        );

        // At round 14: 3s + 14*0.5s = 10s (exactly at cap)
        state.view = 14;
        assert_eq!(
            state.current_view_change_timeout(),
            max_timeout,
            "At round 14: should be exactly at cap (10s)"
        );

        // At round 20: would be 13s, but capped at 10s
        state.view = 20;
        assert_eq!(
            state.current_view_change_timeout(),
            max_timeout,
            "At round 20: should be capped at 10s"
        );

        // At round 100: would be 53s, but capped at 10s
        state.view = 100;
        assert_eq!(
            state.current_view_change_timeout(),
            max_timeout,
            "At round 100: should still be capped at 10s"
        );
    }

    #[test]
    fn test_linear_backoff_no_cap_tendermint_style() {
        let keys: Vec<Bls12381G1PrivateKey> = (0..4).map(|_| generate_bls_keypair()).collect();
        let validators: Vec<ValidatorInfo> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: k.public_key(),
                voting_power: 1,
            })
            .collect();
        let validator_set = ValidatorSet::new(validators);
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));

        // Configure with no cap (Tendermint behavior)
        let config = BftConfig::default().with_view_change_timeout_max(None);

        let mut state = BftState::new(
            0,
            {
                let key_bytes = keys[0].to_bytes();
                Bls12381G1PrivateKey::from_bytes(&key_bytes).expect("valid key bytes")
            },
            topology,
            config,
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));

        let base_timeout = Duration::from_secs(3);
        let increment = Duration::from_millis(500);

        // At round 100: 3s + 100*0.5s = 53s (no cap)
        state.view = 100;
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout + increment * 100,
            "At round 100 with no cap: should be 53s"
        );

        // At round 1000: 3s + 1000*0.5s = 503s (no cap)
        state.view = 1000;
        assert_eq!(
            state.current_view_change_timeout(),
            base_timeout + increment * 1000,
            "At round 1000 with no cap: should be 503s (~8.4 minutes)"
        );
    }
}
