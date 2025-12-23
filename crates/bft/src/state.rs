//! BFT consensus state machine.
//!
//! This module implements the BFT consensus state machine
//! as a synchronous, event-driven model.

use hyperscale_core::{Action, Event, OutboundMessage, SubStateMachine, TimerId};

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
    Block, BlockHeader, BlockHeight, BlockVote, CommitmentProof, Hash, KeyPair, PublicKey,
    QuorumCertificate, RoutableTransaction, ShardGroupId, Topology, TransactionAbort,
    TransactionCertificate, TransactionDefer, ValidatorId, VotePower,
};
use std::borrow::Cow;
use std::collections::HashMap;
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
}

/// Vote pending signature verification.
#[derive(Debug, Clone)]
struct PendingVoteVerification {
    /// The vote awaiting verification.
    vote: BlockVote,
    /// Voting power of the voter.
    voting_power: u64,
    /// Committee index of the voter.
    committee_index: usize,
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
    signing_key: KeyPair,

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
    /// Used to detect stale pending blocks that should be removed to allow sync.
    pending_block_created_at: HashMap<Hash, Duration>,

    /// Vote sets for blocks (hash -> vote set).
    vote_sets: HashMap<Hash, VoteSet>,

    /// Vote locking: tracks which block hash we voted for at each height.
    /// Critical for BFT safety - prevents voting for conflicting blocks at the same height,
    /// even across different rounds. This is the core safety invariant of BFT consensus.
    ///
    /// Key: height, Value: (block_hash, round)
    /// We also track the round to allow re-voting for the SAME block in a later round
    /// (which is safe), while preventing votes for DIFFERENT blocks at the same height.
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

    /// Votes pending signature verification.
    /// Maps (block_hash, voter) -> (vote, voting_power, committee_index).
    /// Once verified, these are processed as if just received.
    pending_vote_verifications: HashMap<(Hash, ValidatorId), PendingVoteVerification>,

    /// Block headers pending QC signature verification.
    /// Maps block_hash -> pending verification info.
    /// When we receive a block header with non-genesis parent_qc, we must verify
    /// the QC's aggregated BLS signature before voting on the block.
    pending_qc_verifications: HashMap<Hash, PendingQcVerification>,

    /// Synced blocks pending QC signature verification.
    /// Maps block_hash -> pending synced block info.
    /// When we receive a synced block, we must verify its QC's signature before applying.
    pending_synced_block_verifications: HashMap<Hash, PendingSyncedBlockVerification>,

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
        signing_key: KeyPair,
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
            pending_vote_verifications: HashMap::new(),
            pending_qc_verifications: HashMap::new(),
            pending_synced_block_verifications: HashMap::new(),
            verified_qcs: HashMap::new(),
            buffered_synced_blocks: std::collections::BTreeMap::new(),
            pending_commits: std::collections::BTreeMap::new(),
            pending_commits_awaiting_data: HashMap::new(),
            config,
            now: Duration::ZERO,
            last_proposal_time: Duration::ZERO,
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
    fn public_key(&self, validator_id: ValidatorId) -> Option<PublicKey> {
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

    /// Check if pipeline backpressure should prevent proposing.
    ///
    /// Returns true if the gap between QC height and committed height exceeds the limit.
    /// This prevents runaway pipelining where QC advances faster than commits can follow,
    /// which can cause slower validators to fall behind and eventually lose quorum.
    fn pipeline_backpressure(&self) -> bool {
        let qc_height = self.latest_qc.as_ref().map(|qc| qc.height.0).unwrap_or(0);
        qc_height > self.committed_height + self.config.pipeline_backpressure_limit
    }

    /// Get committee index for a validator.
    fn committee_index(&self, validator_id: ValidatorId) -> Option<usize> {
        self.topology.local_committee_index(validator_id)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Signature Message Construction
    // ═══════════════════════════════════════════════════════════════════════════

    /// Create the message bytes to sign for a block vote.
    ///
    /// Includes domain separation to prevent cross-shard replay attacks:
    /// - Domain tag ("block_vote:")
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
        self.genesis_block = Some(genesis.clone());
        self.committed_hash = hash;

        info!(
            validator = ?self.validator_id(),
            genesis_hash = ?hash,
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

        // Clean up any votes for heights at or below the committed height.
        // This handles the case where we loaded votes from storage that are now stale.
        self.cleanup_old_state(height.0);

        info!(
            validator = ?self.validator_id(),
            committed_height = self.committed_height,
            committed_hash = ?self.committed_hash,
            has_qc = qc.is_some(),
            "Recovered chain state from storage"
        );

        // Set timers to resume consensus and background tasks
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

    // ═══════════════════════════════════════════════════════════════════════════
    // Proposer Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle proposal timer firing.
    /// Handle proposal timer - build and broadcast a new block.
    ///
    /// Takes ready transactions from mempool, plus deferrals, aborts, and certificates from execution.
    #[instrument(skip(self, mempool, deferred, aborted, certificates, commitment_proofs), fields(
        tx_count = mempool.len(),
        deferred_count = deferred.len(),
        aborted_count = aborted.len(),
        cert_count = certificates.len(),
        proof_count = commitment_proofs.len()
    ))]
    pub fn on_proposal_timer(
        &mut self,
        mempool: &[Arc<RoutableTransaction>],
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
        let mut actions = vec![Action::SetTimer {
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

        // Check pipeline backpressure - if QC is too far ahead of commits, wait.
        // This prevents runaway pipelining that can cause slower validators to fall
        // behind and eventually lose quorum.
        if self.pipeline_backpressure() {
            let qc_height = self.latest_qc.as_ref().map(|qc| qc.height.0).unwrap_or(0);
            info!(
                validator = ?self.validator_id(),
                qc_height = qc_height,
                committed_height = self.committed_height,
                gap = qc_height.saturating_sub(self.committed_height),
                limit = self.config.pipeline_backpressure_limit,
                "Pipeline backpressure - skipping proposal to let commits catch up"
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

        // Build and broadcast block - parent is the latest certified block
        let (parent_hash, parent_qc) = if let Some(qc) = &self.latest_qc {
            (qc.block_hash, qc.clone())
        } else {
            (self.committed_hash, QuorumCertificate::genesis())
        };

        // Select transactions from mempool (limit by config)
        let transactions: Vec<Arc<RoutableTransaction>> = mempool
            .iter()
            .take(self.config.max_transactions_per_block)
            .map(Arc::clone)
            .collect();

        let timestamp = self.now.as_millis() as u64;
        let block_height = BlockHeight(next_height);

        // Set block_height on each deferral (proposer fills this in)
        let deferred_with_height: Vec<TransactionDefer> = deferred
            .into_iter()
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

        let header = BlockHeader {
            height: block_height,
            parent_hash,
            parent_qc: parent_qc.clone(),
            proposer: self.validator_id(),
            timestamp,
            round,
            is_fallback: false,
        };

        // Collect certificate hashes from pending blocks that will commit before our new block.
        // These blocks are at heights between committed_height+1 and next_height-1.
        // When they commit, their certificates will be removed from local storage,
        // so other validators won't be able to validate our block if it includes them.
        let pending_commit_cert_hashes: std::collections::HashSet<Hash> = self
            .pending_blocks
            .values()
            .filter(|pending| {
                let h = pending.header().height.0;
                h > self.committed_height && h < next_height
            })
            .filter_map(|pending| pending.block())
            .flat_map(|block| {
                block
                    .committed_certificates
                    .iter()
                    .map(|c| c.transaction_hash)
                    .collect::<Vec<_>>()
            })
            .collect();

        // Include certificates (limit by config), excluding those already in pending-commit blocks
        let committed_certificates: Vec<_> = certificates
            .into_iter()
            .filter(|c| !pending_commit_cert_hashes.contains(&c.transaction_hash))
            .take(self.config.max_certificates_per_block)
            .collect();

        // Build set of certificate hashes being committed in this block
        let cert_hash_set: std::collections::HashSet<Hash> = committed_certificates
            .iter()
            .map(|c| c.transaction_hash)
            .collect();

        // Filter out stale deferrals - those whose winner OR loser is being committed in this block.
        // A deferral is "stale" if either:
        // 1. The winner TX already has a certificate - cycle resolved, deferral not needed
        // 2. The deferred TX (loser) already has a certificate - loser completed before defer
        let deferred_with_height: Vec<TransactionDefer> = deferred_with_height
            .into_iter()
            .filter(|d| {
                let hyperscale_types::DeferReason::LivelockCycle { winner_tx_hash } = &d.reason;
                !cert_hash_set.contains(winner_tx_hash) && !cert_hash_set.contains(&d.tx_hash)
            })
            .collect();

        let block = Block {
            header: header.clone(),
            transactions: transactions.clone(),
            committed_certificates: committed_certificates.clone(),
            deferred: deferred_with_height.clone(),
            aborted: aborted_with_height.clone(),
            commitment_proofs: commitment_proofs.clone(),
        };

        let block_hash = block.hash();
        let tx_hashes: Vec<Hash> = transactions.iter().map(|tx| tx.hash()).collect();

        let cert_hashes: Vec<Hash> = committed_certificates
            .iter()
            .map(|c| c.transaction_hash)
            .collect();

        info!(
            validator = ?self.validator_id(),
            height = next_height,
            round = round,
            block_hash = ?block_hash,
            transactions = tx_hashes.len(),
            certificates = cert_hashes.len(),
            "Proposing block"
        );

        // Store our own block as pending (already complete)
        let mut pending = PendingBlock::with_proofs(
            header.clone(),
            tx_hashes.clone(),
            cert_hashes.clone(),
            deferred_with_height.clone(),
            aborted_with_height.clone(),
            commitment_proofs.clone(),
        );
        for tx in &transactions {
            pending.add_transaction_arc(Arc::clone(tx));
        }
        for cert in &committed_certificates {
            pending.add_certificate(Arc::clone(cert));
        }
        if let Ok(constructed) = pending.construct_block() {
            self.pending_blocks.insert(block_hash, pending);
            self.pending_block_created_at.insert(block_hash, self.now);
            self.certified_blocks
                .insert(block_hash, ((*constructed).clone(), parent_qc));
        }

        // Create gossip message - include commitment proofs for ordering validation
        let gossip = hyperscale_messages::BlockHeaderGossip::full(
            header,
            tx_hashes,
            cert_hashes,
            deferred_with_height,
            aborted_with_height,
            commitment_proofs,
        );

        // Track proposal time for rate limiting
        self.last_proposal_time = self.now;

        actions.push(Action::BroadcastToShard {
            shard: self.local_shard(),
            message: OutboundMessage::BlockHeader(Box::new(gossip)),
        });

        // Vote for our own block
        actions.extend(self.create_vote(block_hash, next_height, round));

        actions
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

        let header = BlockHeader {
            height: BlockHeight(height),
            parent_hash,
            parent_qc: parent_qc.clone(),
            proposer: self.validator_id(),
            timestamp,
            round,
            is_fallback: true,
        };

        let block = Block {
            header: header.clone(),
            transactions: vec![], // Empty - fallback blocks have no transactions
            committed_certificates: vec![], // Empty
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
        let mut pending = PendingBlock::new(header.clone(), vec![], vec![]);
        if let Ok(constructed) = pending.construct_block() {
            self.pending_blocks.insert(block_hash, pending);
            self.pending_block_created_at.insert(block_hash, self.now);
            self.certified_blocks
                .insert(block_hash, ((*constructed).clone(), parent_qc));
        }

        // Create gossip message (fallback blocks have no transactions, deferrals, or aborts)
        let gossip = hyperscale_messages::BlockHeaderGossip::new(header, vec![]);

        // Track proposal time for rate limiting
        self.last_proposal_time = self.now;

        actions.push(Action::BroadcastToShard {
            shard: self.local_shard(),
            message: OutboundMessage::BlockHeader(Box::new(gossip)),
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
        let tx_hashes = pending.all_transaction_hashes();
        let cert_hashes = pending.all_certificate_hashes();
        let deferred = pending.deferred().to_vec();
        let aborted = pending.aborted().to_vec();
        let commitment_proofs = pending.commitment_proofs().clone();

        info!(
            validator = ?self.validator_id(),
            height = height,
            original_round = original_round,
            block_hash = ?block_hash,
            tx_count = tx_hashes.len(),
            cert_count = cert_hashes.len(),
            "Re-proposing vote-locked block after view change (keeping original round)"
        );

        // Create and broadcast the gossip message - include commitment proofs for ordering validation
        let gossip = hyperscale_messages::BlockHeaderGossip::full(
            header,
            tx_hashes,
            cert_hashes,
            deferred,
            aborted,
            commitment_proofs,
        );

        actions.push(Action::BroadcastToShard {
            shard: self.local_shard(),
            message: OutboundMessage::BlockHeader(Box::new(gossip)),
        });

        // Note: We do NOT create a new vote here - we already voted for this block
        // at this height. The vote is recorded in voted_heights and our original
        // vote should still be valid (votes are for block_hash + height, not round).

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
    #[instrument(skip(self, header, tx_hashes, cert_hashes, deferred, aborted, mempool, certificates), fields(
        height = header.height.0,
        round = header.round,
        proposer = ?header.proposer,
        tx_count = tx_hashes.len()
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_header(
        &mut self,
        header: BlockHeader,
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

        // Check if this header reveals we're missing blocks and need to sync.
        // The parent_qc certifies block at height N-1 for a block at height N.
        //
        // We check if we actually have the parent block (at parent_height) in any state:
        // - committed (already persisted)
        // - pending_blocks (received via consensus, may be waiting for transactions)
        // - certified_blocks (has QC, waiting for 2-chain commit)
        // - pending_synced_block_verifications (received via sync, verifying QC)
        //
        // Only trigger sync if we're genuinely missing the block, not just because
        // commits are lagging behind due to the pipelined 2-chain commit rule.
        if !header.parent_qc.is_genesis() {
            let parent_height = header.parent_qc.height.0;

            // IMPORTANT: Update latest_qc from the header BEFORE checking if we need sync.
            // This ensures that even when we return early for sync, our latest_qc reflects
            // the highest QC we've seen from the network. Without this, a validator that
            // falls behind would have a stale latest_qc and sync to outdated targets.
            let should_update_qc = self
                .latest_qc
                .as_ref()
                .is_none_or(|existing| header.parent_qc.height.0 > existing.height.0);
            if should_update_qc {
                debug!(
                    validator = ?self.validator_id(),
                    qc_height = header.parent_qc.height.0,
                    "Updated latest_qc from received block header (before sync check)"
                );
                self.latest_qc = Some(header.parent_qc.clone());
                self.maybe_unlock_for_qc(&header.parent_qc);
            }

            // Check if we have the parent block in any form
            if !self.has_block_at_height(parent_height) {
                let target_height = parent_height;
                let target_hash = header.parent_qc.block_hash;

                info!(
                    validator = ?self.validator_id(),
                    committed_height = self.committed_height,
                    parent_height = parent_height,
                    target_height = target_height,
                    "Missing parent block, triggering sync"
                );

                return vec![Action::StartSync {
                    target_height,
                    target_hash,
                }];
            }
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

        // Check if we already have this block
        if self.pending_blocks.contains_key(&block_hash) {
            trace!("Already have pending block {}", block_hash);
            return vec![];
        }

        // Create pending block with deferrals, aborts, and commitment proofs
        let mut pending = PendingBlock::with_proofs(
            header.clone(),
            tx_hashes.clone(),
            cert_hashes.clone(),
            deferred,
            aborted,
            commitment_proofs,
        );

        // Try to fill in transactions from mempool
        for tx_hash in &tx_hashes {
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

        // Check if we have buffered votes for this block that can now form a QC
        // (Votes may arrive before the header due to network timing)
        let mut actions = vec![];
        let total_power = self.total_voting_power();
        let validator_id = self.validator_id();
        if let Some(vote_set) = self.vote_sets.get_mut(&block_hash) {
            // Update the vote set with header info (needed for parent_block_hash in QC)
            vote_set.set_header(&header);

            // Check if we now have quorum
            if vote_set.has_quorum(total_power) {
                info!(
                    validator = ?validator_id,
                    block_hash = ?block_hash,
                    height = height,
                    voting_power = vote_set.voting_power(),
                    "Header arrived, quorum already reached - forming QC"
                );

                match vote_set.build_qc(block_hash) {
                    Ok(qc) => {
                        actions.push(Action::EnqueueInternal {
                            event: Event::QuorumCertificateFormed { block_hash, qc },
                        });
                    }
                    Err(e) => {
                        warn!("Failed to build QC after header arrival: {}", e);
                    }
                }
            }
        }

        if !actions.is_empty() {
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
    fn collect_qc_signer_keys(&self, _qc: &QuorumCertificate) -> Option<Vec<PublicKey>> {
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
        // BFT Safety: A validator must NEVER vote for conflicting blocks at the same height,
        // even across different rounds. This prevents equivocation attacks.
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
            }
        }

        // Create and send vote
        self.create_vote(block_hash, height, round)
    }

    /// Validate deferrals and aborts in a proposed block.
    ///
    /// # Validation Rules
    ///
    /// ## Deferrals (TransactionDefer)
    /// Always enforced (structural rules):
    /// - Hash ordering: deferred_hash > winner_hash (lower hash wins cycles)
    /// - Staleness: winner cert not in same block
    /// - Staleness: loser cert not in same block (loser already completed)
    ///
    /// Optimistic acceptance: If we don't have local state for the TX, we accept
    /// the deferral trusting the proposer. This avoids blocking consensus on mempool
    /// sync differences between nodes.
    ///
    /// ## Aborts (TransactionAbort)
    /// - ExecutionTimeout: Structural rules only (timeout threshold is proposer's call)
    /// - TooManyRetries: Structural rules only (retry count is in the abort itself)
    fn validate_deferrals_and_aborts(&self, block: &Block) -> Result<(), String> {
        use hyperscale_types::{AbortReason, DeferReason};
        use std::collections::HashSet;

        // Build set of certificate hashes in this block for staleness checks
        let cert_hashes: HashSet<Hash> = block
            .committed_certificates
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

            // Note: We do NOT validate mempool state here (is TX cross-shard, is TX deferrable).
            // Per design Decision #6, we use optimistic acceptance - if we don't have the TX
            // in our mempool, we trust the proposer. This avoids blocking consensus due to
            // mempool state differences between nodes.
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
    /// # Ordering Rules
    ///
    /// Transactions must be ordered in three priority tiers:
    /// 1. **Retries first**: Retry transactions (have `retry_details`), sorted by hash
    /// 2. **With proofs second**: Non-retry TXs with CommitmentProof, sorted by hash
    /// 3. **Others third**: All other TXs, sorted by hash
    ///
    /// Within each tier, transactions must be sorted by hash (ascending).
    ///
    /// # Why This Ordering
    ///
    /// - **Retries** have highest priority because they represent deferred transactions
    ///   that have already been through one execution cycle. Fast inclusion prevents
    ///   stalls and livelock cascades.
    /// - **CommitmentProof TXs** have high priority because other shards are waiting
    ///   on us to process them.
    /// - **Others** are fresh transactions with no urgency.
    ///
    /// # Proof Verification
    ///
    /// Both priority tiers are verifiable from block contents:
    /// - `RetryDetails` is embedded in the transaction itself
    /// - `CommitmentProof` is stored in `block.commitment_proofs`
    fn validate_transaction_ordering(&self, block: &Block) -> Result<(), String> {
        let txs = &block.transactions;

        if txs.is_empty() {
            return Ok(());
        }

        // Split into three tiers based on priority
        let mut retries: Vec<Hash> = Vec::new();
        let mut with_proof: Vec<Hash> = Vec::new();
        let mut others: Vec<Hash> = Vec::new();

        for tx in txs.iter() {
            let tx_hash = tx.hash();
            if tx.is_retry() {
                retries.push(tx_hash);
            } else if block.has_commitment_proof(&tx_hash) {
                with_proof.push(tx_hash);
            } else {
                others.push(tx_hash);
            }
        }

        // Verify each tier is sorted by hash
        for window in retries.windows(2) {
            if window[0] >= window[1] {
                return Err(format!(
                    "Retry transactions not in hash order: {} should be < {}",
                    window[0], window[1]
                ));
            }
        }

        for window in with_proof.windows(2) {
            if window[0] >= window[1] {
                return Err(format!(
                    "CommitmentProof transactions not in hash order: {} should be < {}",
                    window[0], window[1]
                ));
            }
        }

        for window in others.windows(2) {
            if window[0] >= window[1] {
                return Err(format!(
                    "Other transactions not in hash order: {} should be < {}",
                    window[0], window[1]
                ));
            }
        }

        // Verify tier ordering: retries < with_proof < others
        // Track the last index seen in each tier and first index of next tier
        let mut last_retry_idx: Option<usize> = None;
        let mut first_proof_idx: Option<usize> = None;
        let mut last_proof_idx: Option<usize> = None;
        let mut first_other_idx: Option<usize> = None;

        for (i, tx) in txs.iter().enumerate() {
            let tx_hash = tx.hash();
            if tx.is_retry() {
                last_retry_idx = Some(i);
            } else if block.has_commitment_proof(&tx_hash) {
                if first_proof_idx.is_none() {
                    first_proof_idx = Some(i);
                }
                last_proof_idx = Some(i);
            } else if first_other_idx.is_none() {
                first_other_idx = Some(i);
            }
        }

        // Check: all retries must come before all with_proof
        if let (Some(last_retry), Some(first_proof)) = (last_retry_idx, first_proof_idx) {
            if last_retry > first_proof {
                return Err(format!(
                    "Retry transactions must come before CommitmentProof transactions: \
                     found retry at index {} after proof TX at index {}",
                    last_retry, first_proof
                ));
            }
        }

        // Check: all retries must come before all others
        if let (Some(last_retry), Some(first_other)) = (last_retry_idx, first_other_idx) {
            if last_retry > first_other {
                return Err(format!(
                    "Retry transactions must come before other transactions: \
                     found retry at index {} after other TX at index {}",
                    last_retry, first_other
                ));
            }
        }

        // Check: all with_proof must come before all others
        if let (Some(last_proof), Some(first_other)) = (last_proof_idx, first_other_idx) {
            if last_proof > first_other {
                return Err(format!(
                    "CommitmentProof transactions must come before other transactions: \
                     found proof TX at index {} after other TX at index {}",
                    last_proof, first_other
                ));
            }
        }

        Ok(())
    }

    /// Create a vote for a block.
    fn create_vote(&mut self, block_hash: Hash, height: u64, round: u64) -> Vec<Action> {
        // Record that we voted for this block at this height
        // This is the core safety invariant: once we vote for a block at a height,
        // we can never vote for a different block at that height
        self.voted_heights.insert(height, (block_hash, round));

        // Create signature with domain separation (prevents cross-shard replay)
        let signing_message =
            Self::block_vote_message(self.shard_group, height, round, &block_hash);
        let signature = self.signing_key.sign(&signing_message);
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
            message: OutboundMessage::BlockVote(gossip),
        }];

        // Also process our own vote locally
        actions.extend(self.on_block_vote_internal(vote));

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Vote Collection
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle received block vote.
    ///
    /// Note: The sender identity is not passed as a parameter anymore.
    /// Sender identity comes from vote.voter (ValidatorId), which is
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

    /// Internal vote processing (used for both received votes and our own).
    ///
    /// This performs initial validation and then delegates signature verification
    /// to the runner. When verification completes, `on_vote_signature_verified`
    /// is called to complete vote processing.
    ///
    /// For our own vote, we skip signature verification since we just signed it.
    fn on_block_vote_internal(&mut self, vote: BlockVote) -> Vec<Action> {
        let block_hash = vote.block_hash;
        let is_own_vote = vote.voter == self.validator_id();

        // Early out: skip votes for already-committed heights.
        // This prevents wasting crypto resources verifying stale votes, which is
        // critical for avoiding feedback loops under load where crypto backlog
        // delays QC formation, triggering view changes, which generate more votes.
        if vote.height.0 <= self.committed_height {
            trace!(
                vote_height = vote.height.0,
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

        // Check for duplicate pending verification
        let key = (block_hash, vote.voter);
        if self.pending_vote_verifications.contains_key(&key) {
            trace!("Vote verification already pending for {:?}", key);
            return vec![];
        }

        // Skip verification for our own vote - we just signed it, so we trust it.
        // This can happen when our vote is gossiped back to us via the network,
        // or when processing our own vote after creating it.
        if is_own_vote {
            trace!(
                block_hash = ?block_hash,
                "Skipping verification for own block vote"
            );
            // Store pending verification info (needed by on_vote_signature_verified)
            self.pending_vote_verifications.insert(
                key,
                PendingVoteVerification {
                    vote: vote.clone(),
                    voting_power,
                    committee_index: voter_index,
                },
            );
            // Directly process as verified
            return self.on_vote_signature_verified(vote, true);
        }

        // Get public key for verification
        let public_key = match self.public_key(vote.voter) {
            Some(pk) => pk,
            None => {
                warn!("No public key for validator {:?}", vote.voter);
                return vec![];
            }
        };

        // Store pending verification info
        self.pending_vote_verifications.insert(
            key,
            PendingVoteVerification {
                vote: vote.clone(),
                voting_power,
                committee_index: voter_index,
            },
        );

        // Construct signing message with domain separation
        let signing_message = Self::block_vote_message(
            self.shard_group,
            vote.height.0,
            vote.round,
            &vote.block_hash,
        );

        // Delegate signature verification to runner
        vec![Action::VerifyVoteSignature {
            vote,
            public_key,
            signing_message,
        }]
    }

    /// Handle vote signature verification result.
    ///
    /// Called when the runner completes `Action::VerifyVoteSignature`.
    #[instrument(skip(self, vote), fields(
        height = vote.height.0,
        voter = ?vote.voter,
        valid = valid
    ))]
    pub fn on_vote_signature_verified(&mut self, vote: BlockVote, valid: bool) -> Vec<Action> {
        let block_hash = vote.block_hash;
        let height = vote.height.0;
        let key = (block_hash, vote.voter);

        // Retrieve pending verification info
        let Some(pending) = self.pending_vote_verifications.remove(&key) else {
            warn!(
                "Vote signature verified but no pending verification for {:?}",
                key
            );
            return vec![];
        };

        // Check verification result
        if !valid {
            warn!(
                "Invalid signature on vote from {:?} for block {}",
                vote.voter, block_hash
            );
            return vec![];
        }

        // HotStuff-2 voting rules: A validator can vote for different blocks at the same height
        // as long as they're at different rounds. This is because validators can unlock their
        // votes when they advance rounds (no QC formed within timeout).
        //
        // Equivocation (Byzantine behavior) is voting for DIFFERENT blocks at the SAME round.
        // Voting for different blocks at different rounds is legitimate HotStuff-2 behavior.
        //
        // We track votes by (height, voter) -> (block_hash, round) to detect true equivocation.
        let vote_key = (height, vote.voter);
        if let Some(&(existing_block, existing_round)) =
            self.received_votes_by_height.get(&vote_key)
        {
            if existing_block != block_hash {
                if vote.round == existing_round {
                    // EQUIVOCATION: Same round, different block - this is Byzantine behavior
                    warn!(
                        voter = ?vote.voter,
                        height = height,
                        round = vote.round,
                        existing_block = ?existing_block,
                        new_block = ?block_hash,
                        "EQUIVOCATION DETECTED: validator voted for different blocks at same height AND round"
                    );
                    // TODO: Generate equivocation proof for slashing
                    return vec![];
                } else if vote.round < existing_round {
                    // Old vote from a previous round - ignore it (we already have a newer vote)
                    trace!(
                        voter = ?vote.voter,
                        height = height,
                        old_round = vote.round,
                        new_round = existing_round,
                        "Ignoring old vote from previous round"
                    );
                    return vec![];
                }
                // vote.round > existing_round: This is a legitimate HotStuff-2 revote after unlock
                // The validator advanced rounds and voted for a new block. This is expected.
                debug!(
                    voter = ?vote.voter,
                    height = height,
                    old_round = existing_round,
                    new_round = vote.round,
                    old_block = ?existing_block,
                    new_block = ?block_hash,
                    "Accepting revote after round advancement (HotStuff-2 unlock)"
                );
            }
            // Same block - this is a duplicate vote (possibly at different round), VoteSet will handle it
        }

        // Pre-compute topology values before mutable borrows
        let committee_size = self.committee().len();
        let total_power = self.total_voting_power();
        let validator_id = self.validator_id();
        let header_for_vote = self
            .pending_blocks
            .get(&block_hash)
            .map(|pb| pb.header().clone());

        // Record that this validator voted for this block at this height and round
        self.received_votes_by_height
            .insert(vote_key, (block_hash, vote.round));

        // Get or create vote set
        let vote_set = self
            .vote_sets
            .entry(block_hash)
            .or_insert_with(|| VoteSet::new(header_for_vote, committee_size));

        // Add vote to set
        if !vote_set.add_vote(pending.vote, pending.committee_index, pending.voting_power) {
            // Duplicate vote within same VoteSet
            return vec![];
        }

        debug!(
            validator = ?validator_id,
            block_hash = ?block_hash,
            voting_power = vote_set.voting_power(),
            total_power = total_power,
            "Vote added (signature verified)"
        );

        // Check for quorum
        if vote_set.has_quorum(total_power) {
            info!(
                validator = ?validator_id,
                block_hash = ?block_hash,
                height = height,
                voting_power = vote_set.voting_power(),
                "Quorum reached, forming QC"
            );

            // Build QC
            match vote_set.build_qc(block_hash) {
                Ok(qc) => {
                    return vec![Action::EnqueueInternal {
                        event: Event::QuorumCertificateFormed { block_hash, qc },
                    }];
                }
                Err(e) => {
                    warn!("Failed to build QC: {}", e);
                }
            }
        }

        vec![]
    }

    /// Handle QC signature verification result.
    ///
    /// Called when the runner completes `Action::VerifyQcSignature`.
    /// If valid, we proceed to vote on the block (for consensus) or apply the block (for sync).
    #[instrument(skip(self), fields(block_hash = ?block_hash, valid = valid))]
    pub fn on_qc_signature_verified(&mut self, block_hash: Hash, valid: bool) -> Vec<Action> {
        // Check if this is a synced block verification
        debug!(
            block_hash = ?block_hash,
            pending_count = self.pending_synced_block_verifications.len(),
            pending_keys = ?self.pending_synced_block_verifications.keys().collect::<Vec<_>>(),
            "on_qc_signature_verified: checking pending_synced_block_verifications"
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

            debug!(
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
                (block.transactions.len(), block.committed_certificates.len())
            } else {
                (0, 0)
            }
        } else if let Some((block, _)) = self.certified_blocks.get(&committable_hash) {
            (block.transactions.len(), block.committed_certificates.len())
        } else {
            (0, 0)
        }
    }

    /// Count transactions in the block that would be committed by a QC.
    ///
    /// Convenience method - returns only the transaction count.
    /// Use `pending_commit_counts` if you also need certificate count.
    pub fn pending_commit_tx_count(&self, qc: &QuorumCertificate) -> usize {
        self.pending_commit_counts(qc).0
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
    #[instrument(skip(self, qc, mempool, deferred, aborted, certificates, commitment_proofs), fields(
        height = qc.height.0,
        block_hash = ?block_hash
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn on_qc_formed(
        &mut self,
        block_hash: Hash,
        qc: QuorumCertificate,
        mempool: &[Arc<RoutableTransaction>],
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
        //
        // TODO: This creates duplicate persistence - blocks are persisted here on QC
        // formation AND again on commit (in on_block_ready_to_commit). RocksDB handles
        // this efficiently (idempotent overwrite), but we should consider either:
        // (a) tracking persisted blocks to skip duplicates, or
        // (b) removing PersistBlock from the commit path for non-synced blocks.
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
                    actions.push(Action::EnqueueInternal {
                        event: Event::BlockReadyToCommit {
                            block_hash: committable_hash,
                            qc: qc.clone(),
                        },
                    });
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
        let round = self.view;

        let has_content = !mempool.is_empty()
            || !deferred.is_empty()
            || !aborted.is_empty()
            || !certificates.is_empty();

        let time_since_last_proposal = self.now.saturating_sub(self.last_proposal_time);
        let rate_limited = time_since_last_proposal < self.config.min_block_interval;

        if has_content && self.should_propose(next_height, round) && !rate_limited {
            debug!(
                validator = ?self.validator_id(),
                next_height = next_height,
                round = round,
                "Immediately proposing next block after QC formation"
            );

            // Propose immediately with actual mempool contents
            actions.extend(self.on_proposal_timer(
                mempool,
                deferred,
                aborted,
                certificates,
                commitment_proofs,
            ));
        } else if has_content && self.should_propose(next_height, round) && rate_limited {
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
        self.commit_block_and_buffered(block_hash, qc)
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
    fn commit_block_and_buffered(
        &mut self,
        block_hash: Hash,
        qc: QuorumCertificate,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut current_hash = block_hash;
        let mut current_qc = qc;

        loop {
            // Get the block to commit
            let block = if let Some(pending) = self.pending_blocks.get(&current_hash) {
                pending.block().map(|b| (*b).clone())
            } else if let Some((block, _)) = self.certified_blocks.get(&current_hash) {
                Some(block.clone())
            } else {
                None
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

            // Clean up old state
            self.cleanup_old_state(height);

            // For sync protocol: we need to store the QC that certifies THIS block.
            //
            // The `current_qc` parameter is the QC for the child block (block N+1) that triggered
            // this commit via the 2-chain rule. Its `aggregated_signature` contains signatures
            // over block N+1's hash, NOT this block's hash.
            //
            // The QC that certifies THIS block (block N) contains signatures over block N's hash.
            // This QC is embedded in the child block's header as `parent_qc`.
            //
            // We look up the child block using `current_qc.block_hash` and extract its `parent_qc`.
            let child_block_hash = current_qc.block_hash;
            let commit_qc = if let Some(pending) = self.pending_blocks.get(&child_block_hash) {
                pending.header().parent_qc.clone()
            } else if let Some((child_block, _)) = self.certified_blocks.get(&child_block_hash) {
                child_block.header.parent_qc.clone()
            } else {
                // Fallback: shouldn't happen in normal operation, but log a warning
                warn!(
                    "Child block {} not found when committing block {}, using block's own parent_qc",
                    child_block_hash, current_hash
                );
                block.header.parent_qc.clone()
            };

            // Emit actions for this block
            actions.push(Action::PersistBlock {
                block: block.clone(),
                qc: commit_qc,
            });
            actions.push(Action::EmitCommittedBlock {
                block: block.clone(),
            });
            actions.push(Action::EnqueueInternal {
                event: Event::BlockCommitted {
                    block_hash: current_hash,
                    height,
                    block: block.clone(),
                },
            });

            // Check if the next height is buffered
            let next_height = height + 1;
            if let Some((next_hash, next_qc)) = self.pending_commits.remove(&next_height) {
                debug!(
                    "Processing buffered commit for height {} after committing {}",
                    next_height, height
                );
                current_hash = next_hash;
                current_qc = next_qc;
            } else {
                // No more buffered commits
                break;
            }
        }

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
    pub fn on_synced_block_ready(&mut self, block: Block, qc: QuorumCertificate) -> Vec<Action> {
        let block_hash = block.hash();
        let height = block.header.height.0;

        // Check if we've already committed this or higher
        if height <= self.committed_height {
            trace!("Synced block at height {} already committed", height);
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
            trace!(
                "Synced block at height {} already pending verification",
                height
            );
            return vec![];
        }
        if self.buffered_synced_blocks.contains_key(&height) {
            trace!("Synced block at height {} already buffered", height);
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
    fn try_drain_buffered_synced_blocks(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();

        // Find the next height we need - accounting for what's already pending verification
        let highest_pending_height = self
            .pending_synced_block_verifications
            .values()
            .map(|p| p.block.header.height.0)
            .max()
            .unwrap_or(self.committed_height);

        let mut next_height = highest_pending_height.max(self.committed_height) + 1;

        // Keep draining as long as we have the next sequential block buffered
        while let Some((block, qc)) = self.buffered_synced_blocks.remove(&next_height) {
            debug!(height = next_height, "Draining buffered synced block");
            actions.extend(self.submit_synced_block_for_verification(block, qc));
            next_height += 1;
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
        self.cleanup_old_state(height);

        // Emit actions for the synced block
        let mut actions = vec![
            Action::PersistBlock {
                block: block.clone(),
                qc,
            },
            Action::EmitCommittedBlock {
                block: block.clone(),
            },
            Action::EnqueueInternal {
                event: Event::BlockCommitted {
                    block_hash,
                    height,
                    block: block.clone(),
                },
            },
        ];

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

        // After applying blocks, check if we can drain buffered blocks
        // Calculate what height we now expect
        let highest_pending_height = self
            .pending_synced_block_verifications
            .values()
            .map(|p| p.block.header.height.0)
            .max()
            .unwrap_or(self.committed_height);
        let mut expected_height = highest_pending_height.max(self.committed_height) + 1;

        // Drain consecutive buffered blocks and submit them for verification
        while let Some((block, qc)) = self.buffered_synced_blocks.remove(&expected_height) {
            debug!(
                expected_height,
                "Draining buffered synced block for verification"
            );
            actions.extend(self.submit_synced_block_for_verification(block, qc));
            expected_height += 1;
        }

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
    #[instrument(skip(self, _mempool, _deferrals, _aborts, _certificates), fields(new_round = self.view + 1))]
    pub fn advance_round(
        &mut self,
        _mempool: &[Arc<RoutableTransaction>],
        _deferrals: Vec<TransactionDefer>,
        _aborts: Vec<TransactionAbort>,
        _certificates: Vec<Arc<TransactionCertificate>>,
    ) -> Vec<Action> {
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

        // HotStuff-2 unlock: If no QC has formed at this height, we can safely
        // clear our vote lock. This is determined by checking if latest_qc is
        // still below our current height.
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
                    "Unlocking vote at height (no QC formed, safe per HotStuff-2)"
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
    pub fn maybe_unlock_for_qc(&mut self, qc: &QuorumCertificate) {
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

    /// Handle transaction fetch timer expiry.
    ///
    /// If the pending block is still incomplete, emit TransactionNeeded
    /// so the runner can request the missing transactions from a peer.
    pub fn on_transaction_fetch_timer(&mut self, block_hash: Hash) -> Vec<Action> {
        let Some(pending) = self.pending_blocks.get(&block_hash) else {
            // Block no longer pending (completed or removed)
            return vec![];
        };

        if pending.is_complete() {
            // Block is now complete, no fetch needed
            return vec![];
        }

        let missing = pending.missing_transactions();
        if missing.is_empty() {
            // Only missing certificates, not transactions
            return vec![];
        }

        let proposer = pending.header().proposer;

        info!(
            validator = ?self.validator_id(),
            block_hash = ?block_hash,
            proposer = ?proposer,
            missing_count = missing.len(),
            "Transaction fetch timer fired - requesting missing transactions"
        );

        vec![Action::FetchTransactions {
            block_hash,
            proposer,
            tx_hashes: missing,
        }]
    }

    /// Handle transactions received from a fetch request.
    ///
    /// Adds the fetched transactions to the pending block and triggers
    /// voting if the block is now complete.
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

    /// Handle certificate fetch timer expiry.
    ///
    /// If the pending block is still missing certificates, emit CertificateNeeded
    /// so the runner can request them from a peer.
    pub fn on_certificate_fetch_timer(&mut self, block_hash: Hash) -> Vec<Action> {
        let Some(pending) = self.pending_blocks.get(&block_hash) else {
            // Block no longer pending (completed or removed)
            return vec![];
        };

        if pending.is_complete() {
            // Block is now complete, no fetch needed
            return vec![];
        }

        let missing = pending.missing_certificates();
        if missing.is_empty() {
            // Only missing transactions, not certificates
            return vec![];
        }

        let proposer = pending.header().proposer;

        info!(
            validator = ?self.validator_id(),
            block_hash = ?block_hash,
            proposer = ?proposer,
            missing_count = missing.len(),
            "Certificate fetch timer fired - requesting missing certificates"
        );

        vec![Action::FetchCertificates {
            block_hash,
            proposer,
            cert_hashes: missing,
        }]
    }

    /// Handle certificates received from a fetch request.
    ///
    /// Adds the fetched certificates to the pending block and triggers
    /// voting if the block is now complete.
    ///
    /// Note: Certificates should be verified by the caller before passing here.
    /// This method assumes the certificates have been validated.
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

    /// Handle permanent fetch failure for a block.
    ///
    /// Called when the runner gives up on fetching transactions/certificates
    /// after max retries. We remove the pending block and any associated buffered
    /// commit to allow sync to be triggered.
    ///
    /// IMPORTANT: If a QC has been formed for this block, we MUST NOT give up.
    /// The block is committed in the consensus view and we need its data to make
    /// progress. In this case, we restart the fetch instead of removing the block.
    ///
    /// TODO: This is a quick fix for a data availability issue. We need to think
    /// more carefully about DA guarantees:
    /// - Should we require complete block data before voting?
    /// - Should proposers persist block data before broadcasting?
    /// - How do we handle the case where the proposer is the only one with the data
    ///   and they crash/disappear?
    pub fn on_fetch_failed(&mut self, block_hash: Hash) -> Vec<Action> {
        // Check if this block has a QC - if so, we MUST get the data eventually
        let has_qc = self.certified_blocks.contains_key(&block_hash)
            || self
                .latest_qc
                .as_ref()
                .map(|qc| qc.block_hash == block_hash)
                .unwrap_or(false);

        if has_qc {
            // Block has a QC - we cannot give up on fetching its data
            if let Some(pending) = self.pending_blocks.get(&block_hash) {
                let height = pending.header().height.0;
                let proposer = pending.header().proposer;
                let missing_txs: Vec<Hash> = pending.missing_transactions();
                let missing_certs: Vec<Hash> = pending.missing_certificates();

                warn!(
                    validator = ?self.validator_id(),
                    block_hash = ?block_hash,
                    height = height,
                    missing_txs = missing_txs.len(),
                    missing_certs = missing_certs.len(),
                    "Fetch failed but block has QC - must retry (block is committed in consensus)"
                );

                let mut actions = Vec::new();

                // Restart transaction fetch if needed
                if !missing_txs.is_empty() {
                    actions.push(Action::FetchTransactions {
                        block_hash,
                        proposer,
                        tx_hashes: missing_txs,
                    });
                }

                // Restart certificate fetch if needed
                if !missing_certs.is_empty() {
                    actions.push(Action::FetchCertificates {
                        block_hash,
                        proposer,
                        cert_hashes: missing_certs,
                    });
                }

                return actions;
            }
        }

        // No QC for this block yet - don't remove it, just stop actively fetching.
        // The block might still complete via:
        // 1. StateCertificate gossip → local TransactionCertificate creation
        // 2. Later fetches triggered by cleanup timer
        // 3. Certificates arriving from other sources
        //
        // The stale_pending_block_timeout will clean up truly dead blocks later.
        if let Some(pending) = self.pending_blocks.get(&block_hash) {
            let height = pending.header().height.0;
            debug!(
                validator = ?self.validator_id(),
                block_hash = ?block_hash,
                height = height,
                missing_txs = pending.missing_transaction_count(),
                missing_certs = pending.missing_certificate_count(),
                "Fetch failed but keeping pending block - may complete via gossip/local creation"
            );
        }

        vec![]
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
        // This fixes a race condition similar to the one for pending_vote_verifications:
        // if another validator's fallback block at round N has already accumulated votes
        // in our vote_sets before we advance to round N, we should preserve those votes.
        // Note: vote_sets are keyed by block_hash, so we need to check the height and round
        self.vote_sets.retain(|_hash, vote_set| {
            // Keep if: different height OR round >= new_round OR round unknown
            vote_set.height().is_none_or(|h| h != height)
                || vote_set.round().is_none_or(|r| r >= new_round)
        });

        // Clear pending vote verifications for this height, but ONLY for rounds
        // less than the new round. Votes at the current or higher rounds are still
        // valid and should complete verification.
        //
        // This fixes a race condition: if another validator creates a fallback block
        // at round N and sends us a vote, we might receive and start verifying it
        // just before our own timer fires and advances us to round N. Without this
        // round check, we'd discard the valid vote and never form a QC.
        let before_pending = self.pending_vote_verifications.len();
        self.pending_vote_verifications.retain(|_, pending| {
            // Keep if: different height OR round >= new_round
            pending.vote.height.0 != height || pending.vote.round >= new_round
        });
        let pending_cleared = before_pending - self.pending_vote_verifications.len();
        if pending_cleared > 0 {
            debug!(
                height,
                new_round,
                pending_cleared,
                "Cleared pending vote verifications for height during view change"
            );
        }

        cleared
    }

    /// Clean up old state after commit.
    fn cleanup_old_state(&mut self, committed_height: u64) {
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

        // Remove pending vote verifications at or below committed height.
        // Verifying votes for already-committed heights is wasted crypto work.
        self.pending_vote_verifications
            .retain(|_, pending| pending.vote.height.0 > committed_height);

        // Remove pending QC verifications for blocks at or below committed height.
        // We look up the block hash in pending_blocks to get the height - if the block
        // is no longer in pending_blocks (was just cleaned up above), we remove the
        // pending verification since we won't need it.
        self.pending_qc_verifications
            .retain(|hash, _| self.pending_blocks.contains_key(hash));

        // Remove verified QC cache entries for heights at or below committed height.
        // We keep entries slightly above committed_height in case of view changes
        // where multiple proposals at the same height share the same parent_qc.
        self.verified_qcs
            .retain(|_, height| *height > committed_height.saturating_sub(2));
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

    /// Clean up stale incomplete pending blocks.
    ///
    /// Removes pending blocks that:
    /// 1. Are incomplete (still waiting for transactions/certificates)
    /// 2. Have been pending longer than `stale_pending_block_timeout`
    ///
    /// This prevents a node from getting stuck when transaction/certificate
    /// fetches fail permanently. By removing stale incomplete blocks, we allow
    /// sync to be triggered when a later block header arrives.
    ///
    /// Returns the number of blocks removed.
    pub fn cleanup_stale_pending_blocks(&mut self) -> usize {
        let timeout = self.config.stale_pending_block_timeout;
        let now = self.now;
        let mut removed = 0;

        // Collect hashes of stale incomplete blocks
        let stale_hashes: Vec<Hash> = self
            .pending_blocks
            .iter()
            .filter(|(hash, pending)| {
                // Only remove incomplete blocks
                if pending.is_complete() {
                    return false;
                }
                // Check if it's been pending too long
                if let Some(&created_at) = self.pending_block_created_at.get(*hash) {
                    now.saturating_sub(created_at) >= timeout
                } else {
                    // No creation time tracked - shouldn't happen, but remove anyway
                    true
                }
            })
            .map(|(hash, _)| *hash)
            .collect();

        // Remove stale blocks and their associated buffered commits
        for hash in stale_hashes {
            if let Some(pending) = self.pending_blocks.remove(&hash) {
                let height = pending.header().height.0;
                warn!(
                    validator = ?self.validator_id(),
                    block_hash = ?hash,
                    height = height,
                    missing_txs = pending.missing_transaction_count(),
                    missing_certs = pending.missing_certificate_count(),
                    "Removing stale incomplete pending block to allow sync"
                );
                self.pending_block_created_at.remove(&hash);

                // Also clean up any buffered commit that was waiting for this block's data.
                // Without this, the entry would stay in pending_commits_awaiting_data forever.
                self.pending_commits_awaiting_data.remove(&hash);

                removed += 1;
            }
        }

        removed
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

        // Check if we can make progress from our current position.
        // The critical check is whether we have a COMPLETE block at the next height
        // we need to commit. Having blocks at higher heights doesn't help if we're
        // stuck on an earlier incomplete block.
        let next_needed_height = self.committed_height + 1;

        // Log sync health status when behind
        let gap = qc_height.saturating_sub(self.committed_height);
        if gap > 5 {
            let has_next = self.has_complete_block_at_height(next_needed_height);
            let pending_commit_count = self.pending_commits.len();
            let pending_data_count = self.pending_commits_awaiting_data.len();
            debug!(
                validator = ?self.validator_id(),
                committed_height = self.committed_height,
                next_needed_height = next_needed_height,
                qc_height = qc_height,
                gap = gap,
                has_next_complete = has_next,
                pending_commits = pending_commit_count,
                pending_commits_awaiting_data = pending_data_count,
                certified_blocks = self.certified_blocks.len(),
                pending_blocks = self.pending_blocks.len(),
                "Sync health check status"
            );
        }

        if self.has_complete_block_at_height(next_needed_height) {
            // We have the next block ready - commits should proceed normally
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
                    "Have complete block at next height but significantly behind - triggering sync to recover"
                );
                // Force sync to get the correct blocks from the canonical chain
                return vec![Action::StartSync {
                    target_height: qc_height,
                    target_hash: qc_hash,
                }];
            }
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

        vec![Action::StartSync {
            target_height: qc_height,
            target_hash: qc_hash,
        }]
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

    /// Get the BFT configuration.
    pub fn config(&self) -> &BftConfig {
        &self.config
    }

    /// Get the voted heights map (for testing/debugging).
    pub fn voted_heights(&self) -> &HashMap<u64, (Hash, u64)> {
        &self.voted_heights
    }

    /// Check if we have a block at the given height in any state.
    ///
    /// Returns true if we have the block in:
    /// - `pending_blocks` (received header, may be waiting for transactions)
    /// - `certified_blocks` (has QC, waiting for commit)
    /// - `pending_synced_block_verifications` (received via sync, verifying QC)
    /// - `buffered_synced_blocks` (received via sync, waiting for earlier blocks)
    ///
    /// This is used to determine if we need to sync for a block.
    ///
    /// Note: We include ALL pending_blocks (even incomplete ones) because:
    /// 1. Incomplete blocks will eventually be cleaned up by `cleanup_stale_pending_blocks()`
    /// 2. The cleanup timer runs every second, so stale blocks won't prevent sync for long
    /// 3. Being too aggressive about triggering sync causes performance issues
    fn has_block_at_height(&self, height: u64) -> bool {
        // Already committed
        if height <= self.committed_height {
            return true;
        }

        // In pending blocks (received via consensus)
        if self
            .pending_blocks
            .values()
            .any(|pb| pb.header().height.0 == height)
        {
            return true;
        }

        // In certified blocks (has QC, waiting for commit)
        if self
            .certified_blocks
            .values()
            .any(|(block, _)| block.header.height.0 == height)
        {
            return true;
        }

        // In pending synced block verifications
        if self
            .pending_synced_block_verifications
            .values()
            .any(|p| p.block.header.height.0 == height)
        {
            return true;
        }

        // In buffered synced blocks (waiting for earlier blocks)
        if self.buffered_synced_blocks.contains_key(&height) {
            return true;
        }

        false
    }

    /// Check if we have a COMPLETE block at the given height that can be committed.
    ///
    /// Unlike `has_block_at_height`, this only returns true if the block is fully
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

impl SubStateMachine for BftState {
    fn try_handle(&mut self, event: &Event) -> Option<Vec<Action>> {
        match event {
            Event::ProposalTimer => {
                // Note: In real usage, mempool, deferrals, certificates, and proofs would be passed in
                Some(self.on_proposal_timer(&[], vec![], vec![], vec![], HashMap::new()))
            }
            Event::BlockHeaderReceived {
                header,
                tx_hashes,
                cert_hashes,
                deferred,
                aborted,
                commitment_proofs,
            } => Some(self.on_block_header(
                header.clone(),
                tx_hashes.clone(),
                cert_hashes.clone(),
                deferred.clone(),
                aborted.clone(),
                commitment_proofs.clone(),
                &HashMap::new(), // In real usage, mempool would be passed
                &HashMap::new(), // In real usage, certificates would be passed
            )),
            Event::BlockVoteReceived { vote } => Some(self.on_block_vote(vote.clone())),
            Event::QuorumCertificateFormed { block_hash, qc } => {
                // Note: In SubStateMachine context, we pass empty mempool, deferrals, aborts, certs, and proofs.
                // The NodeStateMachine should handle this event directly with actual data.
                Some(self.on_qc_formed(
                    *block_hash,
                    qc.clone(),
                    &[],
                    vec![],
                    vec![],
                    vec![],
                    HashMap::new(),
                ))
            }
            Event::BlockReadyToCommit { block_hash, qc } => {
                Some(self.on_block_ready_to_commit(*block_hash, qc.clone()))
            }
            Event::BlockCommitted { .. } => Some(vec![]),
            Event::VoteSignatureVerified { vote, valid } => {
                Some(self.on_vote_signature_verified(vote.clone(), *valid))
            }
            Event::QcSignatureVerified { block_hash, valid } => {
                Some(self.on_qc_signature_verified(*block_hash, *valid))
            }
            Event::ChainMetadataFetched { height, hash, qc } => {
                Some(self.on_chain_metadata_fetched(*height, *hash, qc.clone()))
            }
            _ => None,
        }
    }

    fn set_time(&mut self, now: Duration) {
        self.now = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        Signature, SignerBitfield, StaticTopology, ValidatorInfo, ValidatorSet,
    };

    fn make_test_state() -> BftState {
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();

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

        BftState::new(
            0,
            keys[0].clone(),
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

        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[1].clone(),
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
            aggregated_signature: Signature::zero(), // Dummy for test
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
        };

        // Process the block header
        let actions = state.on_block_header(
            header,
            vec![],
            vec![],
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

        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[1].clone(),
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
            aggregated_signature: Signature::zero(),
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
        };

        let block_hash = header.hash();

        // First, process header to trigger QC verification
        let _ = state.on_block_header(
            header,
            vec![],
            vec![],
            vec![],
            vec![],
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

        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[1].clone(),
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
            aggregated_signature: Signature::zero(),
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
        };

        let block_hash = header.hash();

        // Process header to add pending verification
        let _ = state.on_block_header(
            header,
            vec![],
            vec![],
            vec![],
            vec![],
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

        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[1].clone(),
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
        };

        // Process header
        let actions = state.on_block_header(
            header,
            vec![],
            vec![],
            vec![],
            vec![],
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
        let _actions = state.advance_round(&[], vec![], vec![], vec![]);

        assert_eq!(state.view, initial_view + 1, "View should increment by 1");
    }

    #[test]
    fn test_advance_round_proposer_broadcasts() {
        use hyperscale_core::Action;

        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[2].clone(),
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));

        // Advance to round 1 - validator 2 becomes proposer
        let actions = state.advance_round(&[], vec![], vec![], vec![]);

        // Should broadcast a fallback block
        let has_broadcast = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastToShard { .. }));
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
        let _actions = state.advance_round(&[], vec![], vec![], vec![]);

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
            aggregated_signature: Signature::zero(),
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
            aggregated_signature: Signature::zero(),
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
            aggregated_signature: Signature::zero(),
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

    fn make_test_block(
        height: u64,
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        certificates: Vec<hyperscale_types::TransactionCertificate>,
    ) -> Block {
        Block {
            header: make_header_at_height(height, 100_000),
            transactions: vec![],
            committed_certificates: certificates.into_iter().map(Arc::new).collect(),
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
            proof: None, // Proof validation tested separately
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
            proof: None, // Proof validation tested separately
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
            proof: None, // Proof validation tested separately
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
            proof: None, // Proof validation tested separately
        };
        let block = make_test_block(5, vec![deferral], vec![], vec![loser_cert]);
        let result = state.validate_deferrals_and_aborts(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stale"));
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
    fn make_multi_validator_state() -> (BftState, Vec<KeyPair>) {
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[0].clone(),
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

    #[test]
    fn test_equivocation_detection_rejects_conflicting_votes() {
        let (mut state, keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 1u64;
        let round = 0u64; // Same round for both votes - true equivocation
        let voter = ValidatorId(1);

        // Create two different blocks at the same height
        let block_a_hash = Hash::from_bytes(b"block_a_at_height_1");
        let block_b_hash = Hash::from_bytes(b"block_b_at_height_1");

        // Create vote for block A from validator 1 at round 0
        let vote_a = BlockVote {
            block_hash: block_a_hash,
            height: BlockHeight(height),
            round,
            voter,
            signature: keys[1].sign(block_a_hash.as_bytes()),
            timestamp: 100_000,
        };

        // Create vote for block B from SAME validator 1 at SAME round (equivocation!)
        let vote_b = BlockVote {
            block_hash: block_b_hash,
            height: BlockHeight(height),
            round, // Same round - this is true equivocation
            voter,
            signature: keys[1].sign(block_b_hash.as_bytes()),
            timestamp: 100_001,
        };

        // First, simulate successful signature verification for vote A
        state.pending_vote_verifications.insert(
            (block_a_hash, voter),
            PendingVoteVerification {
                vote: vote_a.clone(),
                voting_power: 1,
                committee_index: 1,
            },
        );
        let _actions = state.on_vote_signature_verified(vote_a, true);
        // Vote A should be accepted
        assert!(
            state
                .received_votes_by_height
                .contains_key(&(height, voter)),
            "Vote A should be recorded"
        );
        assert_eq!(
            state.received_votes_by_height.get(&(height, voter)),
            Some(&(block_a_hash, round))
        );

        // Now try to add vote B (equivocation attempt at same round)
        state.pending_vote_verifications.insert(
            (block_b_hash, voter),
            PendingVoteVerification {
                vote: vote_b.clone(),
                voting_power: 1,
                committee_index: 1,
            },
        );
        let actions = state.on_vote_signature_verified(vote_b, true);

        // Vote B should be REJECTED (equivocation detected - same height AND round)
        assert!(actions.is_empty(), "Equivocating vote should be rejected");

        // We should still be tracking vote A
        assert_eq!(
            state.received_votes_by_height.get(&(height, voter)),
            Some(&(block_a_hash, round)),
            "Original vote should still be tracked"
        );

        // Vote set for block B should NOT have this vote
        if let Some(vote_set) = state.vote_sets.get(&block_b_hash) {
            assert_eq!(
                vote_set.voting_power(),
                0,
                "Equivocating vote should not be added to vote set"
            );
        }
    }

    #[test]
    fn test_hotstuff2_allows_revote_at_higher_round() {
        // HotStuff-2 allows validators to vote for different blocks at the same height
        // if they're at different rounds (due to unlock on round advancement).
        // This is NOT equivocation - it's legitimate behavior after timeout.
        let (mut state, keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 1u64;
        let voter = ValidatorId(1);

        // Create two different blocks at the same height
        let block_a_hash = Hash::from_bytes(b"block_a_at_height_1");
        let block_b_hash = Hash::from_bytes(b"block_b_at_height_1");

        // Create vote for block A at round 0
        let vote_a = BlockVote {
            block_hash: block_a_hash,
            height: BlockHeight(height),
            round: 0,
            voter,
            signature: keys[1].sign(block_a_hash.as_bytes()),
            timestamp: 100_000,
        };

        // Create vote for block B at round 1 (after round advancement)
        let vote_b = BlockVote {
            block_hash: block_b_hash,
            height: BlockHeight(height),
            round: 1, // Higher round - legitimate revote
            voter,
            signature: keys[1].sign(block_b_hash.as_bytes()),
            timestamp: 100_001,
        };

        // Add pending block B so we can vote on it
        // For height=1, round=1: proposer = (1 + 1) % 4 = 2
        let parent_qc = QuorumCertificate::genesis();
        let header_b = BlockHeader {
            height: BlockHeight(height),
            parent_hash: parent_qc.block_hash,
            parent_qc: parent_qc.clone(),
            proposer: ValidatorId(2), // Correct proposer for (height=1, round=1)
            timestamp: 100_001,
            round: 1,
            is_fallback: true,
        };
        state
            .pending_blocks
            .insert(block_b_hash, PendingBlock::new(header_b, vec![], vec![]));

        // Add vote A
        state.pending_vote_verifications.insert(
            (block_a_hash, voter),
            PendingVoteVerification {
                vote: vote_a.clone(),
                voting_power: 1,
                committee_index: 1,
            },
        );
        state.on_vote_signature_verified(vote_a, true);

        // Vote A should be recorded at round 0
        assert_eq!(
            state.received_votes_by_height.get(&(height, voter)),
            Some(&(block_a_hash, 0))
        );

        // Now add vote B at higher round - should be ACCEPTED (HotStuff-2 revote)
        state.pending_vote_verifications.insert(
            (block_b_hash, voter),
            PendingVoteVerification {
                vote: vote_b.clone(),
                voting_power: 1,
                committee_index: 1,
            },
        );
        let _actions = state.on_vote_signature_verified(vote_b, true);

        // Vote B should be ACCEPTED (different round = legitimate revote)
        // Note: actions may be empty because quorum isn't reached yet (1 vote != quorum)
        // The key test is that the vote was accepted and tracking was updated.

        // Tracking should now show vote B at round 1 (higher round replaces lower)
        assert_eq!(
            state.received_votes_by_height.get(&(height, voter)),
            Some(&(block_b_hash, 1)),
            "Higher round vote should replace lower round vote"
        );

        // Vote set for block B should have the vote
        assert!(
            state.vote_sets.contains_key(&block_b_hash),
            "Vote should create a vote set for block B"
        );
        let vote_set = state.vote_sets.get(&block_b_hash).unwrap();
        assert_eq!(vote_set.voting_power(), 1, "Vote set should have 1 vote");
    }

    #[test]
    fn test_equivocation_detection_allows_same_block_duplicate() {
        let (mut state, keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let height = 1u64;
        let voter = ValidatorId(1);
        let block_hash = Hash::from_bytes(b"block_at_height_1");

        // Create two identical votes for the same block
        let vote1 = BlockVote {
            block_hash,
            height: BlockHeight(height),
            round: 0,
            voter,
            signature: keys[1].sign(block_hash.as_bytes()),
            timestamp: 100_000,
        };

        let vote2 = BlockVote {
            block_hash,
            height: BlockHeight(height),
            round: 0,
            voter,
            signature: keys[1].sign(block_hash.as_bytes()),
            timestamp: 100_001, // Slightly different timestamp but same block
        };

        // Add first vote
        state.pending_vote_verifications.insert(
            (block_hash, voter),
            PendingVoteVerification {
                vote: vote1.clone(),
                voting_power: 1,
                committee_index: 1,
            },
        );
        state.on_vote_signature_verified(vote1, true);

        // Add second vote for same block - should not trigger equivocation warning
        // (VoteSet will reject as duplicate, but equivocation check passes)
        state.pending_vote_verifications.insert(
            (block_hash, voter),
            PendingVoteVerification {
                vote: vote2.clone(),
                voting_power: 1,
                committee_index: 1,
            },
        );
        let actions = state.on_vote_signature_verified(vote2, true);

        // Actions should be empty (duplicate vote rejected by VoteSet)
        assert!(actions.is_empty(), "Duplicate vote should be rejected");

        // But we should still have the original vote tracked
        assert_eq!(
            state.received_votes_by_height.get(&(height, voter)),
            Some(&(block_hash, 0)) // round 0
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
        };
        let original_block_hash = original_header.hash();

        // Add to pending_blocks (simulating receiving the header)
        let pending = PendingBlock::full(
            original_header.clone(),
            vec![], // no transactions
            vec![], // no certificates
            vec![], // no deferred
            vec![], // no aborted
        );
        state.pending_blocks.insert(original_block_hash, pending);

        // Simulate voting for this block
        state
            .voted_heights
            .insert(height, (original_block_hash, original_round));

        // Now call repropose_locked_block (simulating view change where we're the new leader)
        let actions = state.repropose_locked_block(original_block_hash, height);

        // Should have broadcast action
        let broadcast_action = actions.iter().find(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });
        assert!(
            broadcast_action.is_some(),
            "Should broadcast the re-proposed block"
        );

        // Extract the header from the broadcast
        if let Some(Action::BroadcastToShard {
            message: OutboundMessage::BlockHeader(gossip),
            ..
        }) = broadcast_action
        {
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
        let _actions = state.advance_round(&[], vec![], vec![], vec![]);
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
        let _actions = state.advance_round(&[], vec![], vec![], vec![]);
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
        let actions = state.advance_round(&[], vec![], vec![], vec![]);
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
        let has_broadcast = actions.iter().any(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });
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
            aggregated_signature: Signature::zero(),
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
        let _actions = state.advance_round(&[], vec![], vec![], vec![]);

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
            aggregated_signature: Signature::zero(),
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
            aggregated_signature: Signature::zero(),
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
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[0].clone(),
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
        };
        let original_block_hash = original_header.hash();

        // Add to pending blocks and vote for it
        let pending = PendingBlock::new(original_header, vec![], vec![]);
        state.pending_blocks.insert(original_block_hash, pending);
        state.voted_heights.insert(1, (original_block_hash, 0));

        // Advance to round 3 where we become the proposer
        // Since no QC at height 1, vote lock is cleared, then we create fallback
        state.view = 2; // Will become 3 after advance_round

        let actions = state.advance_round(&[], vec![], vec![], vec![]);

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
        let broadcast_action = actions.iter().find(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });
        assert!(
            broadcast_action.is_some(),
            "Should broadcast fallback block when becoming proposer after view change"
        );

        // Verify it's a fallback block (not the original)
        if let Some(Action::BroadcastToShard {
            message: OutboundMessage::BlockHeader(gossip),
            ..
        }) = broadcast_action
        {
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
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[0].clone(),
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );
        state.set_time(Duration::from_secs(100));

        // No vote lock at height 1 - we haven't voted yet
        assert!(!state.voted_heights.contains_key(&1));

        // Advance to round 3 where we become proposer
        state.view = 2;
        let actions = state.advance_round(&[], vec![], vec![], vec![]);

        // Should create and broadcast a fallback block
        let broadcast_action = actions.iter().find(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });
        assert!(
            broadcast_action.is_some(),
            "Should broadcast fallback block"
        );

        // Extract and verify it's a fallback block
        if let Some(Action::BroadcastToShard {
            message: OutboundMessage::BlockHeader(gossip),
            ..
        }) = broadcast_action
        {
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
            aggregated_signature: Signature::zero(),
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
    fn test_clear_vote_tracking_preserves_current_round_votes() {
        // Test that pending vote verifications at the current/higher round are preserved.
        // This is critical to prevent the race condition where we discard valid votes.
        let (mut state, keys) = make_multi_validator_state();

        let height = 5u64;
        let block_hash = Hash::from_bytes(b"test_block");

        // Add pending vote verifications at different rounds
        // Round 1 - should be cleared when advancing to round 2
        state.pending_vote_verifications.insert(
            (block_hash, ValidatorId(0)),
            PendingVoteVerification {
                vote: BlockVote {
                    block_hash,
                    height: BlockHeight(height),
                    round: 1,
                    voter: ValidatorId(0),
                    signature: keys[0].sign(block_hash.as_bytes()),
                    timestamp: 100_000,
                },
                voting_power: 1,
                committee_index: 0,
            },
        );

        // Round 2 - should be preserved when advancing to round 2
        state.pending_vote_verifications.insert(
            (block_hash, ValidatorId(1)),
            PendingVoteVerification {
                vote: BlockVote {
                    block_hash,
                    height: BlockHeight(height),
                    round: 2,
                    voter: ValidatorId(1),
                    signature: keys[1].sign(block_hash.as_bytes()),
                    timestamp: 100_001,
                },
                voting_power: 1,
                committee_index: 1,
            },
        );

        // Round 3 - should be preserved when advancing to round 2
        state.pending_vote_verifications.insert(
            (block_hash, ValidatorId(2)),
            PendingVoteVerification {
                vote: BlockVote {
                    block_hash,
                    height: BlockHeight(height),
                    round: 3,
                    voter: ValidatorId(2),
                    signature: keys[2].sign(block_hash.as_bytes()),
                    timestamp: 100_002,
                },
                voting_power: 1,
                committee_index: 2,
            },
        );

        // Different height - should be preserved regardless of round
        state.pending_vote_verifications.insert(
            (block_hash, ValidatorId(3)),
            PendingVoteVerification {
                vote: BlockVote {
                    block_hash,
                    height: BlockHeight(6), // Different height
                    round: 0,
                    voter: ValidatorId(3),
                    signature: keys[3].sign(block_hash.as_bytes()),
                    timestamp: 100_003,
                },
                voting_power: 1,
                committee_index: 3,
            },
        );

        assert_eq!(state.pending_vote_verifications.len(), 4);

        // Clear tracking for height 5, advancing to round 2
        state.clear_vote_tracking_for_height(height, 2);

        // Round 1 vote should be cleared (round < new_round)
        assert!(
            !state
                .pending_vote_verifications
                .contains_key(&(block_hash, ValidatorId(0))),
            "Round 1 vote should be cleared"
        );

        // Round 2 vote should be preserved (round >= new_round)
        assert!(
            state
                .pending_vote_verifications
                .contains_key(&(block_hash, ValidatorId(1))),
            "Round 2 vote should be preserved"
        );

        // Round 3 vote should be preserved (round >= new_round)
        assert!(
            state
                .pending_vote_verifications
                .contains_key(&(block_hash, ValidatorId(2))),
            "Round 3 vote should be preserved"
        );

        // Different height vote should be preserved
        assert!(
            state
                .pending_vote_verifications
                .contains_key(&(block_hash, ValidatorId(3))),
            "Different height vote should be preserved"
        );

        assert_eq!(
            state.pending_vote_verifications.len(),
            3,
            "Should have 3 remaining verifications"
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
        };
        let block_hash_h6 = header_height6.hash();

        // Create vote sets with accumulated votes
        let mut vote_set_r1 = VoteSet::new(Some(header_round1), 4);
        vote_set_r1.add_vote(
            BlockVote {
                block_hash: block_hash_r1,
                height: BlockHeight(height),
                round: 1,
                voter: ValidatorId(0),
                signature: keys[0].sign(block_hash_r1.as_bytes()),
                timestamp: 100_000,
            },
            0,
            1,
        );
        state.vote_sets.insert(block_hash_r1, vote_set_r1);

        let mut vote_set_r2 = VoteSet::new(Some(header_round2), 4);
        vote_set_r2.add_vote(
            BlockVote {
                block_hash: block_hash_r2,
                height: BlockHeight(height),
                round: 2,
                voter: ValidatorId(1),
                signature: keys[1].sign(block_hash_r2.as_bytes()),
                timestamp: 100_001,
            },
            1,
            1,
        );
        state.vote_sets.insert(block_hash_r2, vote_set_r2);

        let mut vote_set_r3 = VoteSet::new(Some(header_round3), 4);
        vote_set_r3.add_vote(
            BlockVote {
                block_hash: block_hash_r3,
                height: BlockHeight(height),
                round: 3,
                voter: ValidatorId(2),
                signature: keys[2].sign(block_hash_r3.as_bytes()),
                timestamp: 100_002,
            },
            2,
            1,
        );
        state.vote_sets.insert(block_hash_r3, vote_set_r3);

        let mut vote_set_h6 = VoteSet::new(Some(header_height6), 4);
        vote_set_h6.add_vote(
            BlockVote {
                block_hash: block_hash_h6,
                height: BlockHeight(6),
                round: 0,
                voter: ValidatorId(3),
                signature: keys[3].sign(block_hash_h6.as_bytes()),
                timestamp: 100_003,
            },
            3,
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
            state.vote_sets.get(&block_hash_r2).unwrap().voting_power(),
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
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        // Call on_qc_formed with empty content
        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &[],            // empty mempool
            vec![],         // no deferrals
            vec![],         // no aborts
            vec![],         // no certificates
            HashMap::new(), // no commitment proofs
        );

        // Should NOT contain a BlockHeader broadcast (no proposal)
        let has_block_header = actions.iter().any(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });

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
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        // Create a deferral to include
        use hyperscale_types::{DeferReason, TransactionDefer};
        let deferral = TransactionDefer {
            tx_hash: Hash::from_bytes(b"deferred_tx"),
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: Hash::from_bytes(b"winner_tx"),
            },
            block_height: BlockHeight(0), // Will be filled in when included
            proof: None,                  // Proof validation tested separately
        };

        // Call on_qc_formed with a deferral
        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &[],            // empty mempool
            vec![deferral], // has a deferral
            vec![],         // no aborts
            vec![],         // no certificates
            HashMap::new(), // no commitment proofs
        );

        // Should contain a BlockHeader broadcast (proposal triggered)
        let has_block_header = actions.iter().any(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });

        assert!(
            has_block_header,
            "Should propose immediately after QC formation when has deferrals"
        );
    }

    #[test]
    fn test_qc_verification_caching_skips_redundant_verification() {
        // Test that when we see the same QC in multiple block headers (e.g., during
        // view changes), we only verify it once and skip re-verification for subsequent blocks.
        use hyperscale_core::Action;
        use hyperscale_types::SignerBitfield;

        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[0].clone(),
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
            aggregated_signature: Signature::zero(),
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
        };

        // Process first block header
        let actions1 = state.on_block_header(
            header1,
            vec![],
            vec![],
            vec![],
            vec![],
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
        };

        // Process second block header
        let actions2 = state.on_block_header(
            header2,
            vec![],
            vec![],
            vec![],
            vec![],
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
            transactions,
            committed_certificates: vec![],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: HashMap::new(),
        }
    }

    fn make_test_block_with_proofs(
        height: u64,
        transactions: Vec<Arc<hyperscale_types::RoutableTransaction>>,
        commitment_proofs: HashMap<Hash, CommitmentProof>,
    ) -> Block {
        Block {
            header: make_header_at_height(height, 100_000),
            transactions,
            committed_certificates: vec![],
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
        use hyperscale_types::{test_utils, PartitionNumber, ShardGroupId};

        let tx = test_utils::test_transaction(seed);
        let tx_arc = Arc::new(tx);

        let proof = if with_proof {
            let node = test_utils::test_node(seed);
            Some(CommitmentProof::new(
                tx_arc.hash(),
                ShardGroupId(1),
                SignerBitfield::new(4),
                Signature::zero(),
                BlockHeight(1),
                vec![hyperscale_types::StateEntry::new(
                    node,
                    PartitionNumber(0),
                    vec![],
                    None,
                )],
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
        let mut proof_txs = vec![tx1.clone(), tx2.clone()];
        sort_txs_by_hash(&mut proof_txs);

        let mut no_proof_txs = vec![tx3, tx4];
        sort_txs_by_hash(&mut no_proof_txs);

        // Combine: priority first, then non-priority
        let mut txs = proof_txs.clone();
        txs.extend(no_proof_txs);

        // Build proofs map for the block
        let mut proofs = HashMap::new();
        proofs.insert(tx1.hash(), proof1.unwrap());
        proofs.insert(tx2.hash(), proof2.unwrap());

        let block = make_test_block_with_proofs(5, txs, proofs);
        assert!(state.validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn test_validate_transaction_ordering_invalid_proof_group_unsorted() {
        let state = make_test_state();

        // Create priority TXs with proofs
        let (tx1, proof1) = make_test_tx_with_proof(10, true);
        let (tx2, proof2) = make_test_tx_with_proof(20, true);

        // Sort, then reverse (invalid order)
        let mut txs = vec![tx1.clone(), tx2.clone()];
        sort_txs_by_hash(&mut txs);
        txs.reverse();

        // Build proofs map
        let mut proofs = HashMap::new();
        proofs.insert(tx1.hash(), proof1.unwrap());
        proofs.insert(tx2.hash(), proof2.unwrap());

        let block = make_test_block_with_proofs(5, txs, proofs);
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("CommitmentProof transactions not in hash order"));
    }

    #[test]
    fn test_validate_transaction_ordering_invalid_non_priority_before_priority() {
        let state = make_test_state();

        // Non-priority TX comes before priority TX - invalid
        let (no_proof_tx, _) = make_test_tx_with_proof(10, false);
        let (proof_tx, proof) = make_test_tx_with_proof(20, true);

        // Build proofs map (only proof_tx has a proof)
        let mut proofs = HashMap::new();
        proofs.insert(proof_tx.hash(), proof.unwrap());

        // Put non-priority first (invalid)
        let block = make_test_block_with_proofs(5, vec![no_proof_tx, proof_tx], proofs);
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("CommitmentProof transactions must come before other transactions"));
    }

    #[test]
    fn test_validate_transaction_ordering_all_have_proofs() {
        let state = make_test_state();

        // All TXs have proofs - valid as long as sorted
        let (tx1, proof1) = make_test_tx_with_proof(10, true);
        let (tx2, proof2) = make_test_tx_with_proof(20, true);
        let (tx3, proof3) = make_test_tx_with_proof(30, true);

        let mut txs = vec![tx1.clone(), tx2.clone(), tx3.clone()];
        sort_txs_by_hash(&mut txs);

        // Build proofs map
        let mut proofs = HashMap::new();
        proofs.insert(tx1.hash(), proof1.unwrap());
        proofs.insert(tx2.hash(), proof2.unwrap());
        proofs.insert(tx3.hash(), proof3.unwrap());

        let block = make_test_block_with_proofs(5, txs, proofs);
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

        let mut proofs_vec = vec![proof_tx.clone()];
        sort_txs_by_hash(&mut proofs_vec);

        let mut others = vec![regular.clone()];
        sort_txs_by_hash(&mut others);

        // Combine in correct order: retries, then proofs, then others
        let mut txs = Vec::new();
        txs.extend(retries);
        txs.extend(proofs_vec);
        txs.extend(others);

        let mut proofs_map = HashMap::new();
        proofs_map.insert(proof_tx.hash(), proof.unwrap());

        let block = make_test_block_with_proofs(5, txs, proofs_map);
        assert!(state.validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn test_validate_transaction_ordering_invalid_retry_after_proof() {
        let state = make_test_state();

        // Create a retry and a proof TX
        let retry = make_retry_tx(10);
        let (proof_tx, proof) = make_test_tx_with_proof(30, true);

        // Invalid order: proof TX before retry
        let txs = vec![proof_tx.clone(), retry.clone()];

        let mut proofs_map = HashMap::new();
        proofs_map.insert(proof_tx.hash(), proof.unwrap());

        let block = make_test_block_with_proofs(5, txs, proofs_map);
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Retry transactions must come before"),
            "Should detect retry after proof TX"
        );
    }

    #[test]
    fn test_validate_transaction_ordering_invalid_retry_after_other() {
        let state = make_test_state();

        // Create a retry and a regular TX
        let retry = make_retry_tx(10);
        let regular = make_test_tx(30, false);

        // Invalid order: regular TX before retry
        let txs = vec![regular.clone(), retry.clone()];

        let block = make_test_block_with_transactions(5, txs);
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Retry transactions must come before"),
            "Should detect retry after regular TX"
        );
    }

    #[test]
    fn test_validate_transaction_ordering_retries_only() {
        let state = make_test_state();

        // All retries - valid as long as sorted
        let mut txs = vec![make_retry_tx(10), make_retry_tx(20), make_retry_tx(30)];
        sort_txs_by_hash(&mut txs);

        let block = make_test_block_with_transactions(5, txs);
        assert!(state.validate_transaction_ordering(&block).is_ok());
    }

    #[test]
    fn test_validate_transaction_ordering_retries_unsorted() {
        let state = make_test_state();

        // Retries not sorted by hash
        let mut txs = vec![make_retry_tx(10), make_retry_tx(20), make_retry_tx(30)];
        sort_txs_by_hash(&mut txs);
        txs.reverse(); // Make invalid

        let block = make_test_block_with_transactions(5, txs);
        let result = state.validate_transaction_ordering(&block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Retry transactions not in hash order"));
    }

    #[test]
    fn test_pipeline_backpressure_no_qc() {
        let state = make_test_state();

        // No QC yet, committed_height = 0 -> no backpressure
        assert!(!state.pipeline_backpressure());
    }

    #[test]
    fn test_pipeline_backpressure_within_limit() {
        let mut state = make_test_state();

        // Set committed height to 5
        state.committed_height = 5;

        // Set QC at height 10 (gap of 5, within default limit of 12)
        state.latest_qc = Some(QuorumCertificate {
            block_hash: Hash::from_bytes(b"test"),
            height: BlockHeight(10),
            parent_block_hash: Hash::from_bytes(b"parent"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 0,
        });

        // Gap is 5, limit is 12 -> no backpressure
        assert!(!state.pipeline_backpressure());
    }

    #[test]
    fn test_pipeline_backpressure_at_limit() {
        let mut state = make_test_state();

        // Set committed height to 5
        state.committed_height = 5;

        // Set QC at height 17 (gap of exactly 12, at the limit)
        state.latest_qc = Some(QuorumCertificate {
            block_hash: Hash::from_bytes(b"test"),
            height: BlockHeight(17),
            parent_block_hash: Hash::from_bytes(b"parent"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 0,
        });

        // Gap is 12, limit is 12 -> no backpressure (limit is exclusive: qc > committed + limit)
        assert!(!state.pipeline_backpressure());
    }

    #[test]
    fn test_pipeline_backpressure_exceeds_limit() {
        let mut state = make_test_state();

        // Set committed height to 5
        state.committed_height = 5;

        // Set QC at height 18 (gap of 13, exceeds default limit of 12)
        state.latest_qc = Some(QuorumCertificate {
            block_hash: Hash::from_bytes(b"test"),
            height: BlockHeight(18),
            parent_block_hash: Hash::from_bytes(b"parent"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 0,
        });

        // Gap is 13, limit is 12 -> BACKPRESSURE
        assert!(state.pipeline_backpressure());
    }

    #[test]
    fn test_pipeline_backpressure_configurable_limit() {
        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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

        // Create config with smaller limit
        let config = BftConfig {
            pipeline_backpressure_limit: 5,
            ..BftConfig::default()
        };

        let mut state = BftState::new(
            0,
            keys[0].clone(),
            topology,
            config,
            RecoveredState::default(),
        );

        state.committed_height = 10;
        state.latest_qc = Some(QuorumCertificate {
            block_hash: Hash::from_bytes(b"test"),
            height: BlockHeight(16), // Gap of 6, exceeds limit of 5
            parent_block_hash: Hash::from_bytes(b"parent"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 0,
        });

        // Gap is 6, limit is 5 -> BACKPRESSURE
        assert!(state.pipeline_backpressure());
    }

    #[test]
    fn test_min_block_interval_rate_limits_immediate_proposal() {
        // When a QC forms with content but we proposed too recently,
        // the immediate proposal should be rate-limited.
        use hyperscale_types::{DeferReason, TransactionDefer};

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
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        };

        // Create a deferral so there's content to propose
        let deferral = TransactionDefer {
            tx_hash: Hash::from_bytes(b"deferred_tx"),
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: Hash::from_bytes(b"winner_tx"),
            },
            block_height: BlockHeight(0),
            proof: None,
        };

        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &[],            // empty mempool
            vec![deferral], // has content
            vec![],
            vec![],
            HashMap::new(),
        );

        // Should NOT contain a BlockHeader broadcast (rate limited)
        let has_block_header = actions.iter().any(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });

        assert!(
            !has_block_header,
            "Should NOT propose immediately when rate limited (proposed 50ms ago, limit is 150ms)"
        );
    }

    #[test]
    fn test_min_block_interval_allows_proposal_after_interval() {
        // When enough time has passed since the last proposal,
        // immediate proposals should be allowed.
        use hyperscale_types::{DeferReason, TransactionDefer};

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
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        };

        // Create a deferral so there's content to propose
        let deferral = TransactionDefer {
            tx_hash: Hash::from_bytes(b"deferred_tx"),
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: Hash::from_bytes(b"winner_tx"),
            },
            block_height: BlockHeight(0),
            proof: None,
        };

        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &[],            // empty mempool
            vec![deferral], // has content
            vec![],
            vec![],
            HashMap::new(),
        );

        // Should contain a BlockHeader broadcast (enough time passed)
        let has_block_header = actions.iter().any(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });

        assert!(
            has_block_header,
            "Should propose after rate limit interval has passed (200ms > 150ms)"
        );
    }

    #[test]
    fn test_min_block_interval_configurable() {
        // Test that the min_block_interval config is respected.
        use hyperscale_types::{DeferReason, TransactionDefer};

        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[0].clone(),
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
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        };

        let deferral = TransactionDefer {
            tx_hash: Hash::from_bytes(b"deferred_tx"),
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: Hash::from_bytes(b"winner_tx"),
            },
            block_height: BlockHeight(0),
            proof: None,
        };

        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &[],
            vec![deferral],
            vec![],
            vec![],
            HashMap::new(),
        );

        let has_block_header = actions.iter().any(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });

        assert!(
            !has_block_header,
            "Should be rate limited with custom 500ms interval (only 200ms passed)"
        );
    }

    #[test]
    fn test_min_block_interval_zero_disables_rate_limiting() {
        // Test that setting min_block_interval to zero disables rate limiting.
        use hyperscale_types::{DeferReason, TransactionDefer};

        let keys: Vec<KeyPair> = (0..4).map(|_| KeyPair::generate_bls()).collect();
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
            keys[0].clone(),
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
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 1000,
        };

        let deferral = TransactionDefer {
            tx_hash: Hash::from_bytes(b"deferred_tx"),
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: Hash::from_bytes(b"winner_tx"),
            },
            block_height: BlockHeight(0),
            proof: None,
        };

        let actions = state.on_qc_formed(
            qc.block_hash,
            qc,
            &[],
            vec![deferral],
            vec![],
            vec![],
            HashMap::new(),
        );

        let has_block_header = actions.iter().any(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });

        assert!(
            has_block_header,
            "Should allow immediate proposal when min_block_interval is zero"
        );
    }

    #[test]
    fn test_proposal_timer_updates_last_proposal_time() {
        // Verify that on_proposal_timer updates last_proposal_time when a proposal is made.
        let mut state = make_test_state();
        state.set_time(Duration::from_millis(5000));

        // Ensure last_proposal_time starts at zero
        assert_eq!(state.last_proposal_time, Duration::ZERO);

        // Proposer rotation is (height + round) % committee_size.
        // With 4 validators, validator 0 proposes for height 0, 4, 8, etc.
        // Since committed_height=0, next height is 1, and (1+0)%4=1, so validator 1 proposes.
        // We need to set up a QC so that the next height is 4 (validator 0's turn).
        state.latest_qc = Some(QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_3"),
            height: BlockHeight(3),
            parent_block_hash: Hash::from_bytes(b"block_2"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 5000,
        });

        // Now next_height = 4, (4+0)%4=0, so validator 0 proposes
        let actions = state.on_proposal_timer(&[], vec![], vec![], vec![], HashMap::new());

        // Check that a proposal was made
        let proposed = actions.iter().any(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });

        assert!(proposed, "Validator 0 should propose for height 4");

        // Verify last_proposal_time was updated
        assert_eq!(
            state.last_proposal_time,
            Duration::from_millis(5000),
            "last_proposal_time should be updated to current time"
        );
    }
}
