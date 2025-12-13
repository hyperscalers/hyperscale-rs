//! BFT consensus state machine.
//!
//! This module implements the BFT consensus state machine
//! as a synchronous, event-driven model.

use hyperscale_core::{Action, Event, OutboundMessage, SubStateMachine, TimerId};

/// Index type for simulation-only node routing.
/// Production uses ValidatorId (from message signatures) and PeerId (libp2p).
pub type NodeIndex = u32;
use hyperscale_types::{
    Block, BlockHeader, BlockHeight, BlockVote, Hash, KeyPair, PublicKey, QuorumCertificate,
    RoutableTransaction, ShardGroupId, Topology, TransactionAbort, TransactionCertificate,
    TransactionDefer, ValidatorId, VotePower,
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
    /// across different VoteSets. When we receive a vote, we check if this validator
    /// already voted for a DIFFERENT block at this height - if so, we reject the vote
    /// and log the equivocation attempt.
    received_votes_by_height: HashMap<(u64, ValidatorId), Hash>,

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

    /// Buffered commits waiting for earlier blocks to commit first.
    /// Maps height -> (block_hash, QC).
    /// When we receive a BlockReadyToCommit for height N but we're still at committed_height < N-1,
    /// we buffer it here and process it once the earlier blocks are committed.
    /// This handles out-of-order commit events caused by parallel signature verification.
    pending_commits: std::collections::BTreeMap<u64, (Hash, QuorumCertificate)>,

    // ═══════════════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════════════
    config: BftConfig,

    // ═══════════════════════════════════════════════════════════════════════════
    // Time
    // ═══════════════════════════════════════════════════════════════════════════
    /// Current time (set by runner before each handle call).
    now: Duration,
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
            vote_sets: HashMap::new(),
            voted_heights,
            received_votes_by_height: HashMap::new(),
            certified_blocks: HashMap::new(),
            pending_vote_verifications: HashMap::new(),
            pending_qc_verifications: HashMap::new(),
            pending_synced_block_verifications: HashMap::new(),
            pending_commits: std::collections::BTreeMap::new(),
            config,
            now: Duration::ZERO,
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

        // Set initial proposal timer
        vec![Action::SetTimer {
            id: TimerId::Proposal,
            duration: self.config.proposal_interval,
        }]
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

        // Set proposal timer to resume consensus
        vec![Action::SetTimer {
            id: TimerId::Proposal,
            duration: self.config.proposal_interval,
        }]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Proposer Logic
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle proposal timer firing.
    /// Handle proposal timer - build and broadcast a new block.
    ///
    /// Takes ready transactions from mempool, plus deferrals, aborts, and certificates from execution.
    #[instrument(skip(self, mempool, deferred, aborted, certificates), fields(
        tx_count = mempool.len(),
        deferred_count = deferred.len(),
        aborted_count = aborted.len(),
        cert_count = certificates.len()
    ))]
    pub fn on_proposal_timer(
        &mut self,
        mempool: &[Arc<RoutableTransaction>],
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        certificates: Vec<Arc<TransactionCertificate>>,
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
        let mut pending = PendingBlock::full(
            header.clone(),
            tx_hashes.clone(),
            cert_hashes.clone(),
            deferred_with_height.clone(),
            aborted_with_height.clone(),
        );
        for tx in &transactions {
            pending.add_transaction_arc(Arc::clone(tx));
        }
        for cert in &committed_certificates {
            pending.add_certificate(Arc::clone(cert));
        }
        if let Ok(constructed) = pending.construct_block() {
            self.pending_blocks.insert(block_hash, pending);
            self.certified_blocks
                .insert(block_hash, ((*constructed).clone(), parent_qc));
        }

        // Create gossip message
        let gossip = hyperscale_messages::BlockHeaderGossip::full(
            header,
            tx_hashes,
            cert_hashes,
            deferred_with_height,
            aborted_with_height,
        );

        actions.push(Action::BroadcastToShard {
            shard: self.local_shard(),
            message: OutboundMessage::BlockHeader(gossip),
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
            self.certified_blocks
                .insert(block_hash, ((*constructed).clone(), parent_qc));
        }

        // Create gossip message (fallback blocks have no transactions, deferrals, or aborts)
        let gossip = hyperscale_messages::BlockHeaderGossip::new(header, vec![]);

        actions.push(Action::BroadcastToShard {
            shard: self.local_shard(),
            message: OutboundMessage::BlockHeader(gossip),
        });

        // Vote for our own fallback block
        actions.extend(self.create_vote(block_hash, height, round));

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

        info!(
            validator = ?self.validator_id(),
            height = height,
            original_round = original_round,
            block_hash = ?block_hash,
            tx_count = tx_hashes.len(),
            cert_count = cert_hashes.len(),
            "Re-proposing vote-locked block after view change (keeping original round)"
        );

        // Create and broadcast the gossip message
        let gossip = hyperscale_messages::BlockHeaderGossip::full(
            header,
            tx_hashes,
            cert_hashes,
            deferred,
            aborted,
        );

        actions.push(Action::BroadcastToShard {
            shard: self.local_shard(),
            message: OutboundMessage::BlockHeader(gossip),
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

        // Check if this header reveals we're significantly behind and need to sync.
        // The parent_qc certifies block at height N-1 for a block at height N.
        //
        // IMPORTANT: We use committed_height (not latest_qc.height) to determine if
        // we need to sync. The reason is that latest_qc can be updated from:
        // 1. Block headers we receive but can't process (we update latest_qc below)
        // 2. View change certificates/votes
        // In both cases, we may have a high latest_qc without actually having the
        // blocks, which would prevent sync from being triggered.
        //
        // Using committed_height ensures we trigger sync when the incoming block
        // references parents we haven't actually committed.
        //
        // The two-chain commit rule means we may receive blocks 1-2 heights ahead
        // of our committed_height, but anything beyond that requires sync.
        if !header.parent_qc.is_genesis() {
            let parent_height = header.parent_qc.height.0;
            // Trigger sync if the parent QC references a height beyond what we've committed + 2.
            // The +2 accounts for:
            // - Block at committed_height + 1 is pending (waiting for QC to commit committed_height)
            // - Block at committed_height + 2 can be proposed once we have the QC
            if parent_height > self.committed_height + 2 {
                let target_height = parent_height;
                let target_hash = header.parent_qc.block_hash;

                info!(
                    validator = ?self.validator_id(),
                    committed_height = self.committed_height,
                    parent_height = parent_height,
                    target_height = target_height,
                    "Detected we're significantly behind, triggering sync"
                );

                return vec![Action::EnqueueInternal {
                    event: Event::SyncNeeded {
                        target_height,
                        target_hash,
                    },
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

        // Create pending block with deferrals and aborts
        let mut pending = PendingBlock::full(
            header.clone(),
            tx_hashes.clone(),
            cert_hashes.clone(),
            deferred,
            aborted,
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

        // Store pending block
        self.pending_blocks.insert(block_hash, pending);

        // Update our latest_qc from the received header's parent_qc
        // This is how QCs propagate through the network - via block proposals
        if !header.parent_qc.is_genesis() {
            let should_update = self
                .latest_qc
                .as_ref()
                .is_none_or(|existing| header.parent_qc.height.0 > existing.height.0);
            if should_update {
                debug!(
                    validator = ?self.validator_id(),
                    qc_height = header.parent_qc.height.0,
                    "Updated latest_qc from received block header"
                );
                self.latest_qc = Some(header.parent_qc.clone());
            }
        }

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

        // Block not complete yet - start timers to fetch missing data
        if let Some(pending) = self.pending_blocks.get(&block_hash) {
            // Start transaction fetch timer if missing transactions
            if pending.missing_transaction_count() > 0 {
                debug!(
                    validator = ?self.validator_id(),
                    block_hash = ?block_hash,
                    missing_tx_count = pending.missing_transaction_count(),
                    "Starting transaction fetch timer for incomplete block"
                );
                actions.push(Action::SetTimer {
                    id: TimerId::TransactionFetch { block_hash },
                    duration: self.config.transaction_fetch_timeout,
                });
            }

            // Start certificate fetch timer if missing certificates
            if pending.missing_certificate_count() > 0 {
                debug!(
                    validator = ?self.validator_id(),
                    block_hash = ?block_hash,
                    missing_cert_count = pending.missing_certificate_count(),
                    "Starting certificate fetch timer for incomplete block"
                );
                actions.push(Action::SetTimer {
                    id: TimerId::CertificateFetch { block_hash },
                    duration: self.config.certificate_fetch_timeout,
                });
            }
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

        // Validate deferrals and aborts in the block before voting
        if let Some(pending) = self.pending_blocks.get(&block_hash) {
            if let Some(block) = pending.block() {
                if let Err(e) = self.validate_deferrals_and_aborts(&block) {
                    warn!(
                        validator = ?self.validator_id(),
                        block_hash = ?block_hash,
                        error = %e,
                        "Block has invalid deferrals/aborts - not voting"
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
        // The persist action should be handled synchronously by the runner.
        let mut actions = vec![
            Action::PersistOwnVote {
                height: BlockHeight(height),
                round,
                block_hash,
            },
            Action::BroadcastToShard {
                shard: self.local_shard(),
                message: OutboundMessage::BlockVote(gossip),
            },
        ];

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
    fn on_block_vote_internal(&mut self, vote: BlockVote) -> Vec<Action> {
        let block_hash = vote.block_hash;

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

        // Get public key for verification
        let public_key = match self.public_key(vote.voter) {
            Some(pk) => pk,
            None => {
                warn!("No public key for validator {:?}", vote.voter);
                return vec![];
            }
        };

        // Check for duplicate pending verification
        let key = (block_hash, vote.voter);
        if self.pending_vote_verifications.contains_key(&key) {
            trace!("Vote verification already pending for {:?}", key);
            return vec![];
        }

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

        // Check for equivocation: has this validator voted for a DIFFERENT block at this height?
        // This is critical for BFT safety - a validator must not vote for conflicting blocks.
        let vote_key = (height, vote.voter);
        if let Some(&existing_block) = self.received_votes_by_height.get(&vote_key) {
            if existing_block != block_hash {
                // EQUIVOCATION DETECTED: This validator voted for different blocks at the same height!
                // This is Byzantine behavior. Log it and reject the vote.
                warn!(
                    voter = ?vote.voter,
                    height = height,
                    existing_block = ?existing_block,
                    new_block = ?block_hash,
                    "EQUIVOCATION DETECTED: validator voted for different blocks at same height"
                );
                // TODO: In a production system, we might want to generate an equivocation proof
                // that can be used to slash the Byzantine validator's stake.
                return vec![];
            }
            // Same block - this is a duplicate vote, VoteSet will handle it
        }

        // Pre-compute topology values before mutable borrows
        let committee_size = self.committee().len();
        let total_power = self.total_voting_power();
        let validator_id = self.validator_id();
        let header_for_vote = self
            .pending_blocks
            .get(&block_hash)
            .map(|pb| pb.header().clone());

        // Record that this validator voted for this block at this height
        self.received_votes_by_height.insert(vote_key, block_hash);

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

        // QC is valid - proceed to vote on the block
        let height = pending.header.height.0;
        let round = pending.header.round;
        self.try_vote_on_block(block_hash, height, round)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // QC and Commit Logic
    // ═══════════════════════════════════════════════════════════════════════════

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
    #[instrument(skip(self, qc, mempool, deferred, aborted, certificates), fields(
        height = qc.height.0,
        block_hash = ?block_hash
    ))]
    pub fn on_qc_formed(
        &mut self,
        block_hash: Hash,
        qc: QuorumCertificate,
        mempool: &[Arc<RoutableTransaction>],
        deferred: Vec<TransactionDefer>,
        aborted: Vec<TransactionAbort>,
        certificates: Vec<Arc<TransactionCertificate>>,
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
        }

        let mut actions = vec![];

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

        // Immediately try to propose the next block.
        // This is how the QC propagates to other validators - the next block
        // header will include this QC as parent_qc.
        //
        // We check if we're the proposer for the next height at the current round.
        // If we are, we propose immediately rather than waiting for the next timer.
        let next_height = height + 1;
        let round = self.view;

        if self.should_propose(next_height, round) {
            debug!(
                validator = ?self.validator_id(),
                next_height = next_height,
                round = round,
                "Immediately proposing next block after QC formation"
            );

            // Propose immediately with actual mempool contents
            actions.extend(self.on_proposal_timer(mempool, deferred, aborted, certificates));
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
            warn!("Block {} not found for commit", block_hash);
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

        // Calculate the effective "next expected height" accounting for pending verifications
        // This allows multiple blocks to be queued for verification simultaneously
        let highest_pending_height = self
            .pending_synced_block_verifications
            .values()
            .map(|p| p.block.header.height.0)
            .max()
            .unwrap_or(self.committed_height);
        let expected_height = highest_pending_height.max(self.committed_height) + 1;

        // Synced blocks must be sequential (relative to committed or pending)
        if height != expected_height {
            // Allow if we already have this block pending
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
            warn!(
                "Non-sequential sync: expected height {}, got {}",
                expected_height, height
            );
            return vec![];
        }

        // Verify QC matches block
        if qc.block_hash != block_hash {
            warn!(
                "Synced block QC mismatch: block_hash {:?} != qc.block_hash {:?}",
                block_hash, qc.block_hash
            );
            return vec![];
        }

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

        debug!(
            height,
            block_hash = ?block_hash,
            signers = qc.signers.count(),
            "Verifying synced block QC signature"
        );

        // Store pending verification info
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
        }

        // Also cache the parent_qc from the block header if it's newer
        if !block.header.parent_qc.is_genesis()
            && self
                .latest_qc
                .as_ref()
                .is_none_or(|existing| block.header.parent_qc.height.0 > existing.height.0)
        {
            self.latest_qc = Some(block.header.parent_qc.clone());
        }

        // Clean up old state
        self.cleanup_old_state(height);

        // Emit actions
        vec![
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
        ]
    }

    /// Try to apply all consecutive verified synced blocks.
    ///
    /// Called after a synced block's QC is verified. Applies all verified blocks
    /// in height order starting from committed_height + 1.
    fn try_apply_verified_synced_blocks(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();

        loop {
            let next_height = self.committed_height + 1;

            // Find a verified block at the next height
            let block_hash = self
                .pending_synced_block_verifications
                .iter()
                .find(|(_, p)| p.verified && p.block.header.height.0 == next_height)
                .map(|(h, _)| *h);

            let Some(hash) = block_hash else {
                // No verified block at next height - stop
                break;
            };

            // Remove and apply the block
            let pending = self
                .pending_synced_block_verifications
                .remove(&hash)
                .unwrap();
            actions.extend(self.apply_synced_block(pending.block, pending.qc));
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // View Change
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle view change timer firing (BFT-level fallback).
    ///
    /// Note: The primary view change logic is in `ViewChangeState`, which handles
    /// timeout detection, vote collection, and certificate creation. This method
    /// is only called if BftState handles the timer directly (e.g., in tests).
    /// In production, `NodeState` routes the timer to `ViewChangeState` instead.
    pub fn on_view_change_timer(&mut self) -> Vec<Action> {
        vec![Action::SetTimer {
            id: TimerId::ViewChange,
            duration: self.config.view_change_timeout,
        }]
    }

    /// Handle view change completion (round increment).
    ///
    /// When a view change completes:
    /// 1. Update our view/round
    /// 2. Update our latest_qc if the view change certificate has a newer one
    /// 3. If highest_qc is at current height, we already have a QC - just wait for next proposal
    /// 4. If we're the new proposer, build and broadcast a fallback block
    /// 5. Otherwise, restart the proposal timer to wait for the new proposer
    #[instrument(skip(self, highest_qc), fields(height = height, new_round = new_round))]
    pub fn on_view_change_completed(
        &mut self,
        height: u64,
        new_round: u64,
        highest_qc: QuorumCertificate,
    ) -> Vec<Action> {
        // Only update if this is for our current height
        if height != self.committed_height + 1 {
            debug!(
                height = height,
                expected = self.committed_height + 1,
                "View change for unexpected height"
            );
            return vec![];
        }

        // Update our view/round
        self.view = new_round;

        // Update our latest_qc if the view change certificate has a newer one
        // This is critical: if there's a QC at the current height, we should know about it
        //
        // IMPORTANT: If the highest_qc height is significantly ahead of our committed_height,
        // we need to trigger sync. This handles the case where we receive view change
        // votes/certificates from validators who have seen more blocks than us.
        // Without this check, we could update latest_qc to a high height without having
        // the actual blocks, which would prevent the sync trigger in on_block_header
        // (since it uses max(latest_qc.height, committed_height) to determine if we need sync).
        let mut sync_action = None;
        if !highest_qc.is_genesis() {
            let should_update = self
                .latest_qc
                .as_ref()
                .is_none_or(|existing| highest_qc.height.0 > existing.height.0);
            if should_update {
                // Check if we need to sync before updating latest_qc
                // We need sync if the QC references blocks we don't have
                if highest_qc.height.0 > self.committed_height + 1 {
                    info!(
                        validator = ?self.validator_id(),
                        qc_height = highest_qc.height.0,
                        committed_height = self.committed_height,
                        "View change has QC ahead of committed height, triggering sync"
                    );
                    sync_action = Some(Action::EnqueueInternal {
                        event: Event::SyncNeeded {
                            target_height: highest_qc.height.0,
                            target_hash: highest_qc.block_hash,
                        },
                    });
                }
                info!(
                    validator = ?self.validator_id(),
                    qc_height = highest_qc.height.0,
                    qc_block = ?highest_qc.block_hash,
                    "Updating latest_qc from view change certificate"
                );
                self.latest_qc = Some(highest_qc.clone());
            }
        }

        // If the highest_qc is at the current height (the view change height),
        // that means a QC already exists for a block at this height.
        // We need to process this QC to potentially commit blocks and propose the next height.
        //
        // IMPORTANT: Reset the view/round to 0 because the next height (N+1) should start
        // at round 0, not at the view change round. The view change was for height N, not N+1.
        if highest_qc.height.0 == height {
            let next_height = height + 1;

            info!(
                validator = ?self.validator_id(),
                height = height,
                new_round = new_round,
                qc_block = ?highest_qc.block_hash,
                next_height = next_height,
                "QC already exists at view change height, resetting view and triggering QC processing"
            );

            // Reset view to 0 for the next height's proposal
            self.view = 0;

            // Clear vote-lock for the next height if we had one.
            // The previous block at next_height didn't get a QC (hence the view change),
            // so we need to allow proposing a new block at that height.
            // This is safe because the view change certificate proves consensus moved on.
            if self.voted_heights.remove(&next_height).is_some() {
                info!(
                    validator = ?self.validator_id(),
                    height = next_height,
                    "Cleared vote-lock for next height after view change with QC at current height"
                );
            }

            // Emit a QuorumCertificateFormed event so the node state machine can handle it
            // (it has access to mempool data needed for the next proposal).
            let mut actions = vec![Action::EnqueueInternal {
                event: Event::QuorumCertificateFormed {
                    block_hash: highest_qc.block_hash,
                    qc: highest_qc,
                },
            }];
            if let Some(action) = sync_action {
                actions.push(action);
            }
            return actions;
        }

        // If the highest_qc from the view change is for a height BEFORE the current height,
        // then no block at the current height was certified. In this case, it's safe to
        // unlock our vote because:
        //
        // 1. The block we voted for never reached quorum (no QC formed)
        // 2. No honest validator could have committed based on our vote
        // 3. The view change certificate proves consensus has moved on
        //
        // This prevents the deadlock where all validators are locked to an uncertified
        // block and no progress can be made.
        //
        // Reference: https://decentralizedthoughts.github.io/2023-04-01-hotstuff-2/
        // "if the leader obtains a lock (a quorum certificate) from the preceding view,
        // it knows that it has obtained the maximal locked value that possibly exists"
        if highest_qc.height.0 < height {
            // The highest QC is from a previous height, meaning no block at this height
            // was certified. Safe to unlock and reset vote tracking.
            let had_vote = self.voted_heights.remove(&height).is_some();

            // Also clear vote tracking for this height so we accept new votes from
            // validators who previously voted for the uncertified block. This is safe
            // because the view change certificate proves no QC formed.
            let cleared_votes = self.clear_vote_tracking_for_height(height);

            if had_vote || cleared_votes > 0 {
                info!(
                    validator = ?self.validator_id(),
                    height = height,
                    new_round = new_round,
                    highest_qc_height = highest_qc.height.0,
                    cleared_votes = cleared_votes,
                    "Unlocking vote at height (no QC formed, safe per HotStuff-2)"
                );
            }
        }

        info!(
            validator = ?self.validator_id(),
            height = height,
            new_round = new_round,
            "Applied view change"
        );

        // Check if we're the new proposer for this height/round
        if self.should_propose(height, new_round) {
            // Check if we've already voted at this height - if so, we're locked to that block
            // and must re-propose it (not create a new fallback block).
            // NOTE: After the HotStuff-2 unlock above, this will only be true if
            // the highest_qc was at the current height (meaning a QC exists).
            if let Some(&(existing_hash, existing_round)) = self.voted_heights.get(&height) {
                info!(
                    validator = ?self.validator_id(),
                    height = height,
                    existing_round = existing_round,
                    new_round = new_round,
                    existing_block = ?existing_hash,
                    "Vote-locked to certified block at this height, re-proposing"
                );

                // Re-propose the block we're locked to so other validators can vote on it
                let mut actions = self.repropose_locked_block(existing_hash, height);
                if let Some(action) = sync_action {
                    actions.push(action);
                }
                return actions;
            }

            info!(
                validator = ?self.validator_id(),
                height = height,
                new_round = new_round,
                "We are the new proposer after view change - building fallback block"
            );

            // Build and broadcast fallback block
            let mut actions = self.build_and_broadcast_fallback_block(height, new_round);
            if let Some(action) = sync_action {
                actions.push(action);
            }
            return actions;
        }

        // Not the proposer - restart the proposal timer to wait for new proposer
        let mut actions = vec![Action::SetTimer {
            id: TimerId::Proposal,
            duration: self.config.proposal_interval,
        }];
        if let Some(action) = sync_action {
            actions.push(action);
        }
        actions
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

        vec![Action::EnqueueInternal {
            event: Event::TransactionNeeded {
                block_hash,
                proposer,
                missing_tx_hashes: missing,
            },
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
            // Still missing transactions or certificates
            // Could restart timer here for retry, but for now we'll let it timeout
            return vec![];
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
        self.trigger_qc_verification_or_vote(block_hash)
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

        vec![Action::EnqueueInternal {
            event: Event::CertificateNeeded {
                block_hash,
                proposer,
                missing_cert_hashes: missing,
            },
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
            // Still missing transactions or certificates
            return vec![];
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
        self.trigger_qc_verification_or_vote(block_hash)
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
    /// Returns the number of vote entries cleared.
    fn clear_vote_tracking_for_height(&mut self, height: u64) -> usize {
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

        // Clear vote sets for blocks at this height
        // Note: vote_sets are keyed by block_hash, so we need to check the height
        self.vote_sets
            .retain(|_hash, vote_set| vote_set.height().is_none_or(|h| h != height));

        cleared
    }

    /// Clean up old state after commit.
    fn cleanup_old_state(&mut self, committed_height: u64) {
        // Remove pending blocks at or below committed height
        self.pending_blocks
            .retain(|_, pending| pending.header().height.0 > committed_height);

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

    /// Get the BFT configuration.
    pub fn config(&self) -> &BftConfig {
        &self.config
    }

    /// Get the voted heights map (for testing/debugging).
    pub fn voted_heights(&self) -> &HashMap<u64, (Hash, u64)> {
        &self.voted_heights
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
                // Note: In real usage, mempool, deferrals, and certificates would be passed in
                Some(self.on_proposal_timer(&[], vec![], vec![], vec![]))
            }
            Event::ViewChangeTimer => Some(self.on_view_change_timer()),
            Event::BlockHeaderReceived {
                header,
                tx_hashes,
                cert_hashes,
                deferred,
                aborted,
            } => Some(self.on_block_header(
                header.clone(),
                tx_hashes.clone(),
                cert_hashes.clone(),
                deferred.clone(),
                aborted.clone(),
                &HashMap::new(), // In real usage, mempool would be passed
                &HashMap::new(), // In real usage, certificates would be passed
            )),
            Event::BlockVoteReceived { vote } => Some(self.on_block_vote(vote.clone())),
            Event::QuorumCertificateFormed { block_hash, qc } => {
                // Note: In SubStateMachine context, we pass empty mempool, deferrals, aborts, and certs.
                // The NodeStateMachine should handle this event directly with actual data.
                Some(self.on_qc_formed(*block_hash, qc.clone(), &[], vec![], vec![], vec![]))
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
            Event::ViewChangeCompleted {
                height,
                new_round,
                highest_qc,
            } => Some(self.on_view_change_completed(*height, *new_round, highest_qc.clone())),
            Event::ChainMetadataFetched { height, hash, qc } => {
                Some(self.on_chain_metadata_fetched(*height, *hash, qc.clone()))
            }
            // Note: ViewChangeVoteReceived and ViewChangeCertificateReceived are handled
            // by ViewChangeState, not directly by BftState
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

        // Create a block at height 2 with a non-genesis parent QC
        let parent_hash = Hash::from_bytes(b"parent_block");
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
            vec![], // deferred
            vec![], // aborted
            &HashMap::new(),
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

        // Create block header with non-genesis QC
        let parent_hash = Hash::from_bytes(b"parent_block");
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
            &HashMap::new(),
            &HashMap::new(),
        );

        // Now simulate QC signature verified successfully
        let actions = state.on_qc_signature_verified(block_hash, true);

        // Should produce a vote (broadcast)
        let has_broadcast = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastToShard { .. }));
        assert!(has_broadcast, "Should broadcast vote after QC verified");
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

        // Create block header
        let parent_hash = Hash::from_bytes(b"parent_block");
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
            &HashMap::new(),
            &HashMap::new(),
        );

        // Should NOT emit VerifyQcSignature (genesis QC)
        let has_verify_qc = actions
            .iter()
            .any(|a| matches!(a, Action::VerifyQcSignature { .. }));
        assert!(!has_verify_qc, "Genesis QC should skip verification");

        // Should directly vote (broadcast)
        let has_broadcast = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastToShard { .. }));
        assert!(has_broadcast, "Should vote directly for genesis QC block");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Fallback Block Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_fallback_block_on_view_change_if_proposer() {
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

        // Validator 1 - will be proposer at (height=1, round=0) since (1+0)%4 = 1
        let topology = Arc::new(StaticTopology::new(ValidatorId(1), 1, validator_set));
        let mut state = BftState::new(
            1,
            keys[1].clone(),
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));

        // Simulate view change completion at height 1, round 0
        // Validator 1 should be the proposer
        // Pass genesis QC since there's no QC at this height yet
        let actions = state.on_view_change_completed(1, 0, QuorumCertificate::genesis());

        // Should broadcast a fallback block
        let has_broadcast = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastToShard { .. }));
        assert!(has_broadcast, "Proposer should broadcast fallback block");
    }

    #[test]
    fn test_no_fallback_block_if_not_proposer() {
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

        // Validator 0 - NOT the proposer at (height=1, round=0) since (1+0)%4 = 1
        let topology = Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set));
        let mut state = BftState::new(
            0,
            keys[0].clone(),
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );

        state.set_time(Duration::from_secs(100));

        // Simulate view change completion at height 1, round 0
        // Validator 0 is NOT the proposer
        // Pass genesis QC since there's no QC at this height yet
        let actions = state.on_view_change_completed(1, 0, QuorumCertificate::genesis());

        // Should NOT broadcast (just set timer)
        let has_broadcast = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastToShard { .. }));
        assert!(
            !has_broadcast,
            "Non-proposer should not broadcast fallback block"
        );

        // Should set timer to wait for proposer
        let has_timer = actions.iter().any(|a| {
            matches!(
                a,
                Action::SetTimer {
                    id: TimerId::Proposal,
                    ..
                }
            )
        });
        assert!(has_timer, "Should set proposal timer to wait for proposer");
    }

    #[test]
    fn test_fallback_block_inherits_parent_timestamp() {
        use hyperscale_core::OutboundMessage;
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

        // Validator 2 will be proposer at (height=1, round=1) since (1+1)%4 = 2
        let topology = Arc::new(StaticTopology::new(ValidatorId(2), 1, validator_set));
        let mut state = BftState::new(
            2,
            keys[2].clone(),
            topology,
            BftConfig::default(),
            RecoveredState::default(),
        );

        // Set current time way ahead
        state.set_time(Duration::from_secs(1000));

        // Set up a latest_qc with timestamp 500 seconds
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);

        let parent_qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"parent"),
            height: BlockHeight(0),
            parent_block_hash: Hash::ZERO,
            round: 0,
            aggregated_signature: Signature::zero(),
            signers,
            voting_power: VotePower(3),
            weighted_timestamp_ms: 500_000, // Parent timestamp is 500 seconds
        };
        state.latest_qc = Some(parent_qc);

        // Trigger view change - validator 2 is proposer for (height=1, round=1)
        // Pass genesis QC since there's no QC at this height yet
        let actions = state.on_view_change_completed(1, 1, QuorumCertificate::genesis());

        // Find the broadcast action and extract the header
        for action in actions {
            if let Action::BroadcastToShard {
                message: OutboundMessage::BlockHeader(gossip),
                ..
            } = action
            {
                // Fallback block should inherit parent timestamp (500_000), NOT current time (1000_000)
                assert_eq!(
                    gossip.header.timestamp, 500_000,
                    "Fallback block should inherit parent's weighted timestamp"
                );
                assert!(
                    gossip.header.is_fallback,
                    "Should be marked as fallback block"
                );
                assert!(
                    gossip.transaction_hashes.is_empty(),
                    "Fallback block should have no transactions"
                );
                return;
            }
        }
        panic!("Expected BroadcastToShard action with BlockHeader");
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
        let voter = ValidatorId(1);

        // Create two different blocks at the same height
        let block_a_hash = Hash::from_bytes(b"block_a_at_height_1");
        let block_b_hash = Hash::from_bytes(b"block_b_at_height_1");

        // Create vote for block A from validator 1
        let vote_a = BlockVote {
            block_hash: block_a_hash,
            height: BlockHeight(height),
            round: 0,
            voter,
            signature: keys[1].sign(block_a_hash.as_bytes()),
            timestamp: 100_000,
        };

        // Create vote for block B from SAME validator 1 (equivocation!)
        let vote_b = BlockVote {
            block_hash: block_b_hash,
            height: BlockHeight(height),
            round: 1,
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
            Some(&block_a_hash)
        );

        // Now try to add vote B (equivocation attempt)
        state.pending_vote_verifications.insert(
            (block_b_hash, voter),
            PendingVoteVerification {
                vote: vote_b.clone(),
                voting_power: 1,
                committee_index: 1,
            },
        );
        let actions = state.on_vote_signature_verified(vote_b, true);

        // Vote B should be REJECTED (equivocation detected)
        assert!(actions.is_empty(), "Equivocating vote should be rejected");

        // We should still be tracking vote A
        assert_eq!(
            state.received_votes_by_height.get(&(height, voter)),
            Some(&block_a_hash),
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
            Some(&block_hash)
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
                .insert((height, voter), block_hash);
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

    #[test]
    fn test_view_change_with_qc_at_current_height_emits_qc_formed() {
        // When view change completes and highest_qc.height == view_change_height,
        // we should emit QuorumCertificateFormed to process the QC instead of proposing
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let view_change_height = 1u64;
        let new_round = 5u64;

        // Create a QC at the view change height
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_at_height_1"),
            height: BlockHeight(view_change_height),
            parent_block_hash: Hash::from_bytes(b"parent"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        // Trigger view change with this QC
        let actions = state.on_view_change_completed(view_change_height, new_round, qc.clone());

        // Should emit QuorumCertificateFormed, not broadcast a fallback block
        let has_qc_formed = actions.iter().any(|a| {
            matches!(
                a,
                Action::EnqueueInternal {
                    event: Event::QuorumCertificateFormed { .. }
                }
            )
        });
        assert!(
            has_qc_formed,
            "Should emit QuorumCertificateFormed when QC exists at view change height"
        );

        // Should NOT have a broadcast action (we're not proposing)
        let has_broadcast = actions.iter().any(|a| {
            matches!(
                a,
                Action::BroadcastToShard {
                    message: OutboundMessage::BlockHeader(_),
                    ..
                }
            )
        });
        assert!(
            !has_broadcast,
            "Should NOT broadcast when QC exists at view change height"
        );

        // View should be reset to 0 for the next height
        assert_eq!(state.view, 0, "View should be reset to 0 for next height");
    }

    #[test]
    fn test_view_change_updates_latest_qc() {
        // View change should update latest_qc if the certificate has a newer QC
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        // Start with no latest_qc
        assert!(state.latest_qc.is_none());

        // View change at height 1 (committed_height is 0, so committed_height + 1 = 1)
        let view_change_height = 1u64;
        let new_round = 1u64;

        // Create a QC at height 0 (before view change height) - use genesis-like QC
        // Note: The QC is for the parent height, not the view change height itself
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_at_height_0"),
            height: BlockHeight(0),
            parent_block_hash: Hash::from_bytes(b"genesis"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        // Trigger view change with this QC
        state.on_view_change_completed(view_change_height, new_round, qc.clone());

        // latest_qc should be updated (since height 0 > nothing)
        assert!(state.latest_qc.is_some());
        assert_eq!(state.latest_qc.as_ref().unwrap().height.0, 0);
        assert_eq!(state.latest_qc.as_ref().unwrap().block_hash, qc.block_hash);
    }

    #[test]
    fn test_view_change_clears_vote_lock_for_next_height() {
        // When view change completes with QC at current height,
        // we should clear any vote-lock for the next height
        let (mut state, _keys) = make_multi_validator_state();
        state.set_time(Duration::from_secs(100));

        let view_change_height = 1u64;
        let next_height = 2u64;
        let new_round = 5u64;

        // Simulate having voted at the next height (which didn't get a QC)
        let stale_block_hash = Hash::from_bytes(b"stale_block_at_height_2");
        state
            .voted_heights
            .insert(next_height, (stale_block_hash, 0));

        // Create a QC at the view change height
        let qc = QuorumCertificate {
            block_hash: Hash::from_bytes(b"block_at_height_1"),
            height: BlockHeight(view_change_height),
            parent_block_hash: Hash::from_bytes(b"parent"),
            round: 0,
            signers: SignerBitfield::empty(),
            aggregated_signature: Signature::zero(),
            voting_power: VotePower(3),
            weighted_timestamp_ms: 100_000,
        };

        // Trigger view change with this QC
        state.on_view_change_completed(view_change_height, new_round, qc);

        // Vote lock for next height should be cleared
        assert!(
            !state.voted_heights.contains_key(&next_height),
            "Vote lock for next height should be cleared after view change with QC at current height"
        );
    }
}
