//! Execution state machine.
//!
//! Handles transaction execution after blocks are committed.
//!
//! # Transaction Types
//!
//! - **Single-shard**: Execute locally, then vote within shard for BLS signature aggregation.
//! - **Cross-shard**: 2PC protocol with provisioning, voting, and finalization.
//!
//! # Cross-Shard 2PC Protocol
//!
//! ## Phase 1: Provisioning Broadcast
//! When a block commits with cross-shard transactions, each validator broadcasts
//! provisions (state entries for nodes they own) to target shards.
//!
//! ## Phase 2: Provisioning Reception
//! Validators collect provisions from source shards. When (2n+1)/3 quorum is reached
//! for each source shard, provisioning is complete.
//!
//! ## Phase 3: Cross-Shard Execution
//! With provisioned state, validators execute the transaction and create a
//! StateVoteBlock with merkle root of execution results.
//!
//! ## Phase 4: Vote Aggregation
//! Validators broadcast votes to their local shard. When 2f+1 voting power agrees
//! on the same merkle root, a StateCertificate is created and broadcast.
//!
//! ## Phase 5: Finalization
//! Validators collect StateCertificates from all participating shards. When all
//! certificates are received, an TransactionCertificate is created.

use hyperscale_core::{Action, Event, SubStateMachine};
use hyperscale_types::{
    BlockHeight, ExecutionResult, Hash, KeyPair, NodeId, PublicKey, RoutableTransaction,
    ShardGroupId, Signature, StateCertificate, StateEntry, StateProvision, StateVoteBlock,
    Topology, TransactionCertificate, TransactionDecision, ValidatorId, VotePower,
};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, instrument};

use crate::pending::{
    PendingCertificateAggregation, PendingCertificateVerification,
    PendingFetchedCertificateVerification, PendingProvisionBroadcast,
};
use crate::trackers::{CertificateTracker, VoteTracker};

/// Number of blocks to retain committed certificates for peer fetch requests.
/// This allows slow validators to catch up and fetch certificates from peers
/// even after the proposer has committed the block.
const CERTIFICATE_RETENTION_BLOCKS: u64 = 100;

/// Number of blocks to retain executed transaction hashes for deduplication.
/// This prevents re-execution of recently committed transactions while allowing
/// cleanup of old entries to prevent unbounded memory growth.
const EXECUTED_TX_RETENTION_BLOCKS: u64 = 100;

/// Number of blocks to retain early arrival votes/certificates before cleanup.
/// If an early arrival hasn't been processed within this many blocks, it's
/// likely stale and should be removed to prevent unbounded memory growth.
const EARLY_ARRIVAL_RETENTION_BLOCKS: u64 = 1000;

/// Number of blocks to retain verified vote cache entries.
/// Votes older than this are cleaned up regardless of finalization status.
const VERIFIED_VOTE_RETENTION_BLOCKS: u64 = 200;

/// Key type for the pending verifications reverse index.
/// Identifies which type of verification and the secondary key (validator or shard).
/// Note: Provision verification is handled by ProvisionCoordinator.
/// Note: Vote verification is handled by VoteTracker with deferred batch verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingVerificationKey {
    /// Pending certificate verification for a shard.
    Certificate(ShardGroupId),
}

/// Cached result from speculative execution.
///
/// Stored when a block is proposed but before it commits. If the block commits
/// and no conflicting writes have occurred, the cached result is used instead
/// of re-executing the transaction.
#[derive(Debug, Clone)]
pub struct SpeculativeResult {
    /// Execution result (success, state_root, writes).
    pub result: ExecutionResult,
    /// NodeIds that were READ during execution (for invalidation).
    /// Populated from the transaction's declared_reads.
    pub read_set: HashSet<NodeId>,
    /// When this speculative execution was started.
    pub created_at: Duration,
}

/// Execution state machine.
///
/// Handles transaction execution after blocks are committed.
pub struct ExecutionState {
    /// Network topology (single source of truth for committee/shard info).
    topology: Arc<dyn Topology>,

    /// Signing key for creating votes.
    signing_key: KeyPair,

    /// Current time.
    now: Duration,

    /// Transactions that have been executed (deduplication).
    /// Maps tx_hash -> block_height when executed, enabling height-based cleanup.
    executed_txs: HashMap<Hash, u64>,

    /// Finalized transaction certificates ready for block inclusion.
    /// Uses BTreeMap for deterministic iteration order.
    finalized_certificates: BTreeMap<Hash, Arc<TransactionCertificate>>,

    /// Recently committed certificates kept for peer fetch requests.
    /// Maps tx_hash -> (certificate, commit_height).
    /// Certificates are moved here when committed to a block, then pruned
    /// after CERTIFICATE_RETENTION_BLOCKS to allow slow peers to fetch them.
    recently_committed_certificates: HashMap<Hash, (Arc<TransactionCertificate>, u64)>,

    /// Current committed height for pruning recently_committed_certificates.
    committed_height: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Cross-shard state (Phase 1-2: Provisioning)
    // ═══════════════════════════════════════════════════════════════════════
    /// Transactions waiting for provisioning to complete before execution.
    /// Maps tx_hash -> (transaction, block_height)
    /// Note: Provision tracking is handled by ProvisionCoordinator.
    pending_provisioning: HashMap<Hash, (Arc<RoutableTransaction>, u64)>,

    /// Pending provision broadcasts waiting for state fetch.
    /// Maps tx_hash -> PendingProvisionBroadcast
    pending_provision_fetches: HashMap<Hash, PendingProvisionBroadcast>,

    // ═══════════════════════════════════════════════════════════════════════
    // Cross-shard state (Phase 3-4: Voting)
    // ═══════════════════════════════════════════════════════════════════════
    /// Vote trackers for cross-shard transactions.
    /// Maps tx_hash -> VoteTracker
    vote_trackers: HashMap<Hash, VoteTracker>,

    /// State certificates from vote aggregation (local shard's certificate).
    /// Maps tx_hash -> StateCertificate
    state_certificates: HashMap<Hash, StateCertificate>,

    /// Pending certificate aggregations waiting for BLS aggregation callback.
    /// Maps tx_hash -> PendingCertificateAggregation
    pending_cert_aggregations: HashMap<Hash, PendingCertificateAggregation>,

    // ═══════════════════════════════════════════════════════════════════════
    // Cross-shard state (Phase 5: Finalization)
    // ═══════════════════════════════════════════════════════════════════════
    /// Certificate trackers for cross-shard transactions.
    /// Maps tx_hash -> CertificateTracker
    certificate_trackers: HashMap<Hash, CertificateTracker>,

    // ═══════════════════════════════════════════════════════════════════════
    // Early arrivals (before tracking starts)
    // ═══════════════════════════════════════════════════════════════════════
    /// ProvisioningComplete events that arrived before the block was committed.
    /// This can happen when provisions reach quorum before we've seen the block.
    /// Maps tx_hash -> (provisions, first_arrival_height) for cleanup of stale entries.
    early_provisioning_complete: HashMap<Hash, (Vec<StateProvision>, u64)>,

    /// Votes that arrived before tracking started.
    /// Uses HashSet for O(1) deduplication instead of O(n) Vec::contains.
    /// Tracks (votes, first_arrival_height) for cleanup of stale entries.
    early_votes: HashMap<Hash, (HashSet<StateVoteBlock>, u64)>,

    /// Certificates that arrived before tracking started.
    /// Tracks (certificates, first_arrival_height) for cleanup of stale entries.
    early_certificates: HashMap<Hash, (Vec<StateCertificate>, u64)>,

    // ═══════════════════════════════════════════════════════════════════════
    // Pending signature verifications
    // ═══════════════════════════════════════════════════════════════════════
    /// Note: Provision signature verification is handled by ProvisionCoordinator.
    /// Note: Vote signature verification is handled by VoteTracker with deferred batch verification.

    /// Certificates awaiting signature verification.
    /// Maps (tx_hash, shard_id) -> PendingCertificateVerification
    pending_cert_verifications: HashMap<(Hash, ShardGroupId), PendingCertificateVerification>,

    /// Fetched TransactionCertificates awaiting verification of all embedded StateCertificates.
    /// Maps tx_hash -> PendingFetchedCertificateVerification
    pending_fetched_cert_verifications: HashMap<Hash, PendingFetchedCertificateVerification>,

    /// Reverse index: tx_hash -> set of pending verification keys.
    /// Enables O(k) cleanup instead of O(n) where k = verifications for this tx, n = total.
    pending_verifications_by_tx: HashMap<Hash, HashSet<PendingVerificationKey>>,

    /// Cache of already-verified state vote signatures.
    /// Maps (tx_hash, validator_id) -> height when verified.
    /// When we see the same vote again (e.g., during gossiping or retries),
    /// we can skip re-verification and proceed directly to vote aggregation.
    /// The height is stored to enable cleanup of old entries after finalization.
    verified_state_votes: HashMap<(Hash, ValidatorId), u64>,

    /// Reverse index: tx_hash -> set of validator IDs with verified votes.
    /// Enables O(k) cleanup instead of O(n) where k = verified votes for this tx.
    verified_votes_by_tx: HashMap<Hash, HashSet<ValidatorId>>,

    // ═══════════════════════════════════════════════════════════════════════
    // Speculative Execution State
    // ═══════════════════════════════════════════════════════════════════════
    /// Cache of speculative execution results.
    /// Maps tx_hash -> SpeculativeResult
    speculative_results: HashMap<Hash, SpeculativeResult>,

    /// Transaction hashes currently being speculatively executed.
    /// Used for memory-based backpressure and to detect when speculation is in progress.
    speculative_in_flight_txs: HashSet<Hash>,

    /// Index: which speculative txs read from which nodes.
    /// Used for O(1) invalidation when a committed write touches a node.
    /// Maps node_id -> set of tx_hashes that read from that node.
    speculative_reads_index: HashMap<NodeId, HashSet<Hash>>,

    /// Pending speculative executions waiting for callback.
    /// Maps block_hash -> list of transactions being speculatively executed.
    /// Used to retrieve declared_reads when speculative execution completes.
    pending_speculative_executions: HashMap<Hash, Vec<Arc<RoutableTransaction>>>,

    /// Transactions that committed while speculation was in-flight.
    /// When speculation completes, SignExecutionResults is emitted for the runner
    /// to sign and broadcast. Maps tx_hash -> (block_hash, transaction).
    /// This avoids double-execution when commit beats speculation.
    committed_awaiting_speculation: HashMap<Hash, (Hash, Arc<RoutableTransaction>)>,

    // ═══════════════════════════════════════════════════════════════════════
    // Speculative Execution Config
    // ═══════════════════════════════════════════════════════════════════════
    /// Maximum number of transactions to track speculatively (in-flight + cached).
    /// This is a memory limit to prevent unbounded growth.
    speculative_max_txs: usize,

    /// Number of rounds to pause speculation after a view change.
    /// This avoids wasted work when the network is unstable.
    view_change_cooldown_rounds: u64,

    /// Height at which the last view change occurred.
    /// Speculation is paused for a few rounds after view changes to avoid wasted work.
    last_view_change_height: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Speculative Execution Metrics (accumulated counters, reset on read)
    // ═══════════════════════════════════════════════════════════════════════
    /// Count of speculative executions started since last metrics read.
    speculative_started_count: u64,
    /// Count of speculative cache hits since last metrics read.
    /// Includes both early hits (speculation completed before commit) and
    /// late hits (commit arrived before speculation, but waited for it).
    speculative_cache_hit_count: u64,
    /// Count of "late hits" - speculation completed after commit but we waited.
    /// This is a subset of cache_hit_count, tracking the dedup optimization.
    speculative_late_hit_count: u64,
    /// Count of speculative cache misses since last metrics read.
    speculative_cache_miss_count: u64,
    /// Count of speculative results invalidated since last metrics read.
    speculative_invalidated_count: u64,
}

/// Default maximum transactions for speculative execution (in-flight + cached).
pub const DEFAULT_SPECULATIVE_MAX_TXS: usize = 500;

/// Default number of rounds to pause speculation after a view change.
pub const DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS: u64 = 3;
impl ExecutionState {
    /// Create a new execution state machine with default settings.
    pub fn new(topology: Arc<dyn Topology>, signing_key: KeyPair) -> Self {
        Self::with_speculative_config(
            topology,
            signing_key,
            DEFAULT_SPECULATIVE_MAX_TXS,
            DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS,
        )
    }

    /// Create a new execution state machine with custom speculative execution config.
    ///
    /// # Arguments
    /// * `speculative_max_txs` - Maximum transactions to track speculatively (in-flight + cached)
    /// * `view_change_cooldown_rounds` - Rounds to pause speculation after a view change
    pub fn with_speculative_config(
        topology: Arc<dyn Topology>,
        signing_key: KeyPair,
        speculative_max_txs: usize,
        view_change_cooldown_rounds: u64,
    ) -> Self {
        Self {
            topology,
            signing_key,
            now: Duration::ZERO,
            executed_txs: HashMap::new(),
            finalized_certificates: BTreeMap::new(),
            recently_committed_certificates: HashMap::new(),
            committed_height: 0,
            pending_provisioning: HashMap::new(),
            pending_provision_fetches: HashMap::new(),
            vote_trackers: HashMap::new(),
            state_certificates: HashMap::new(),
            pending_cert_aggregations: HashMap::new(),
            certificate_trackers: HashMap::new(),
            early_provisioning_complete: HashMap::new(),
            early_votes: HashMap::new(),
            early_certificates: HashMap::new(),
            pending_cert_verifications: HashMap::new(),
            pending_fetched_cert_verifications: HashMap::new(),
            pending_verifications_by_tx: HashMap::new(),
            verified_state_votes: HashMap::new(),
            verified_votes_by_tx: HashMap::new(),
            speculative_results: HashMap::new(),
            speculative_in_flight_txs: HashSet::new(),
            speculative_reads_index: HashMap::new(),
            pending_speculative_executions: HashMap::new(),
            committed_awaiting_speculation: HashMap::new(),
            speculative_max_txs,
            view_change_cooldown_rounds,
            last_view_change_height: 0,
            speculative_started_count: 0,
            speculative_cache_hit_count: 0,
            speculative_late_hit_count: 0,
            speculative_cache_miss_count: 0,
            speculative_invalidated_count: 0,
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
    #[allow(dead_code)]
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

    /// Get quorum threshold.
    fn quorum_threshold(&self) -> u64 {
        self.topology.local_quorum_threshold()
    }

    /// Check if a transaction is single-shard.
    fn is_single_shard(&self, tx: &RoutableTransaction) -> bool {
        self.topology.is_single_shard_transaction(tx)
    }

    /// Get all shards for a transaction.
    fn all_shards_for_tx(&self, tx: &RoutableTransaction) -> BTreeSet<ShardGroupId> {
        self.topology
            .all_shards_for_transaction(tx)
            .into_iter()
            .collect()
    }

    /// Get provisioning shards for a transaction (remote shards we need state from).
    #[allow(dead_code)]
    fn provisioning_shards_for_tx(&self, tx: &RoutableTransaction) -> Vec<ShardGroupId> {
        self.topology.provisioning_shards(tx)
    }

    /// Determine shard for a node ID.
    fn shard_for_node(&self, node_id: &NodeId) -> ShardGroupId {
        self.topology.shard_for_node_id(node_id)
    }

    /// Get provisioning quorum for a shard.
    fn provisioning_quorum_for_shard(&self, shard: ShardGroupId) -> usize {
        let committee_size = self.topology.committee_size_for_shard(shard);
        if committee_size == 0 {
            1
        } else {
            (2 * committee_size + 1) / 3
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Block Commit Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle block committed - start executing transactions.
    #[instrument(skip(self, transactions), fields(
        height = height,
        block_hash = ?block_hash,
        tx_count = transactions.len()
    ))]
    pub fn on_block_committed(
        &mut self,
        block_hash: Hash,
        height: u64,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Filter out already-executed transactions (dedup)
        let new_txs: Vec<_> = transactions
            .into_iter()
            .filter(|tx| !self.executed_txs.contains_key(&tx.hash()))
            .collect();

        if new_txs.is_empty() {
            return actions;
        }

        tracing::debug!(
            height = height,
            tx_count = new_txs.len(),
            "Starting execution for new transactions"
        );

        // Update committed height for cleanup calculations
        if height > self.committed_height {
            self.committed_height = height;
        }

        // Mark all as executed (for dedup) with current height for later cleanup
        for tx in &new_txs {
            self.executed_txs.insert(tx.hash(), height);
        }

        // Prune old entries to prevent unbounded growth
        self.prune_executed_txs();
        self.prune_early_arrivals();
        self.prune_verified_votes();

        // Separate single-shard and cross-shard transactions
        let (single_shard, cross_shard): (Vec<_>, Vec<_>) =
            new_txs.into_iter().partition(|tx| self.is_single_shard(tx));

        // Handle single-shard transactions (now use voting like cross-shard)
        // All WRITE operations need BLS signature aggregation
        // Check for cached speculative results to avoid re-execution
        let mut txs_needing_execution = Vec::new();
        let mut speculative_hits = Vec::new();
        let mut awaiting_speculation = Vec::new();

        for tx in single_shard {
            let tx_hash = tx.hash();

            if let Some(result) = self.take_speculative_result(&tx_hash) {
                // Speculation completed - use cached result
                self.speculative_in_flight_txs.remove(&tx_hash);
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    "SPECULATIVE HIT: Using cached speculative result"
                );
                speculative_hits.push((tx, result));
            } else if self.speculative_in_flight_txs.contains(&tx_hash) {
                // Speculation still in-flight - wait for it instead of double-executing
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    "SPECULATIVE WAIT: Commit arrived before speculation complete, waiting"
                );
                awaiting_speculation.push(tx);
            } else {
                // No speculation at all - execute normally
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    speculative_results_count = self.speculative_results.len(),
                    in_flight_txs = self.speculative_in_flight_txs.len(),
                    "SPECULATIVE MISS: No cached result, executing normally"
                );
                self.record_speculative_cache_miss();
                txs_needing_execution.push(tx);
            }
        }

        // Process speculative hits - start tracking and emit results for runner to sign
        let mut cached_results = Vec::new();
        for (tx, result) in speculative_hits {
            actions.extend(self.start_single_shard_execution(tx.clone()));
            cached_results.push(result);
        }
        if !cached_results.is_empty() {
            // Runner will sign these results and send StateVoteReceived for each
            actions.push(Action::SignExecutionResults {
                results: cached_results,
            });
        }

        // Track transactions waiting for in-flight speculation to complete.
        // When SpeculativeExecutionComplete arrives, these will be processed.
        for tx in awaiting_speculation {
            let tx_hash = tx.hash();
            // Start execution tracking (vote trackers, etc.) but don't emit ExecuteTransactions
            actions.extend(self.start_single_shard_execution(tx.clone()));
            // Track that this committed tx is waiting for speculation
            self.committed_awaiting_speculation
                .insert(tx_hash, (block_hash, tx));
        }

        // Start execution tracking for transactions that need execution
        for tx in &txs_needing_execution {
            actions.extend(self.start_single_shard_execution(tx.clone()));
        }

        // Batch execute transactions that didn't have cached results
        if !txs_needing_execution.is_empty() {
            actions.push(Action::ExecuteTransactions {
                block_hash,
                transactions: txs_needing_execution,
                state_root: Hash::from_bytes(&[0u8; 32]),
            });
        }

        // Handle cross-shard transactions (2PC)
        for tx in cross_shard {
            actions.extend(self.start_cross_shard_execution(tx, height));
        }

        actions
    }

    /// Start single-shard execution with proper voting.
    ///
    /// Single-shard transactions use the same voting pattern as cross-shard transactions:
    /// 1. Execute locally without provisioning (no cross-shard state needed)
    /// 2. Create a signed vote on the execution result
    /// 3. Broadcast vote within the shard
    /// 4. Vote aggregator collects votes and creates certificate when quorum reached
    ///
    /// This requires BLS signature aggregation for all transactions, not just cross-shard ones.
    fn start_single_shard_execution(&mut self, tx: Arc<RoutableTransaction>) -> Vec<Action> {
        let mut actions = Vec::new();
        let tx_hash = tx.hash();
        let local_shard = self.local_shard();

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            "Starting single-shard execution with voting"
        );

        // Step 1: Start tracking votes (same as cross-shard)
        let quorum = self.quorum_threshold();
        let vote_tracker = VoteTracker::new(
            tx_hash,
            vec![local_shard], // Only our shard participates
            tx.declared_reads.clone(),
            quorum,
        );
        self.vote_trackers.insert(tx_hash, vote_tracker);

        // Step 2: Start tracking certificates for finalization (single shard only)
        let participating_shards: BTreeSet<_> = [local_shard].into_iter().collect();
        let cert_tracker = CertificateTracker::new(tx_hash, participating_shards);
        self.certificate_trackers.insert(tx_hash, cert_tracker);

        // Step 3: Replay any early votes that arrived before tracking started.
        // IMPORTANT: We must go through on_vote() to ensure proper signature verification.
        // Early votes were buffered without verification, so they need to be verified now.
        if let Some((early_votes, _arrival_height)) = self.early_votes.remove(&tx_hash) {
            tracing::debug!(
                tx_hash = ?tx_hash,
                count = early_votes.len(),
                "Replaying early votes for single-shard tx"
            );
            for vote in early_votes {
                // Use on_vote() to ensure signature verification happens
                actions.extend(self.on_vote(vote));
            }
        }

        // Step 4: Replay any early certificates (shouldn't happen often for single-shard).
        // IMPORTANT: We must go through on_certificate() to ensure proper signature verification.
        // Early certificates were buffered without verification, so they need to be verified now.
        if let Some((early_certs, _arrival_height)) = self.early_certificates.remove(&tx_hash) {
            tracing::debug!(
                tx_hash = ?tx_hash,
                count = early_certs.len(),
                "Replaying early certificates for single-shard tx"
            );
            for cert in early_certs {
                // Use on_certificate() to ensure signature verification happens
                actions.extend(self.on_certificate(cert));
            }
        }

        actions
    }

    /// Start cross-shard execution (2PC Phase 1: Provisioning).
    fn start_cross_shard_execution(
        &mut self,
        tx: Arc<RoutableTransaction>,
        height: u64,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let tx_hash = tx.hash();
        let local_shard = self.local_shard();

        // Identify all participating shards
        let participating_shards = self.all_shards_for_tx(&tx);

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            participating = ?participating_shards,
            "Starting cross-shard execution"
        );

        // Phase 1: Initiate provision broadcast (async - fetches state first)
        actions.extend(self.initiate_provision_broadcast(&tx, BlockHeight(height)));

        // Phase 2: Start tracking provisioning
        // Find remote shards we need provisions from
        let remote_shards: BTreeSet<_> = participating_shards
            .iter()
            .filter(|&&s| s != local_shard)
            .copied()
            .collect();

        if remote_shards.is_empty() {
            // No remote state needed - shouldn't happen for cross-shard tx
            // but handle gracefully
            tracing::warn!(tx_hash = ?tx_hash, "Cross-shard tx with no remote shards");
        } else {
            // Build quorum thresholds per shard
            let quorum_thresholds: HashMap<ShardGroupId, usize> = remote_shards
                .iter()
                .map(|&shard| (shard, self.provisioning_quorum_for_shard(shard)))
                .collect();

            // Emit registration event for ProvisionCoordinator
            // The coordinator will handle provision tracking centrally
            actions.push(Action::EnqueueInternal {
                event: Event::CrossShardTxRegistered {
                    tx_hash,
                    required_shards: remote_shards,
                    quorum_thresholds,
                    committed_height: BlockHeight(height),
                },
            });

            // Store transaction for later execution (will execute when ProvisioningComplete arrives)
            self.pending_provisioning
                .insert(tx_hash, (tx.clone(), height));

            // Check if ProvisioningComplete arrived before the block committed
            if let Some((provisions, _arrival_height)) =
                self.early_provisioning_complete.remove(&tx_hash)
            {
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    count = provisions.len(),
                    "Replaying early ProvisioningComplete"
                );
                actions.extend(self.on_provisioning_complete(tx_hash, provisions));
            }
        }

        // Phase 3-4: Start tracking votes
        let quorum = self.quorum_threshold();
        let vote_tracker = VoteTracker::new(
            tx_hash,
            participating_shards.iter().copied().collect(),
            tx.declared_reads.clone(),
            quorum,
        );
        self.vote_trackers.insert(tx_hash, vote_tracker);

        // Phase 5: Start tracking certificates for finalization
        let cert_tracker = CertificateTracker::new(tx_hash, participating_shards.clone());
        self.certificate_trackers.insert(tx_hash, cert_tracker);

        // Replay any early votes.
        // IMPORTANT: We must go through on_vote() to ensure proper signature verification.
        // Early votes were buffered without verification, so they need to be verified now.
        if let Some((early_votes, _arrival_height)) = self.early_votes.remove(&tx_hash) {
            tracing::debug!(tx_hash = ?tx_hash, count = early_votes.len(), "Replaying early votes");
            for vote in early_votes {
                // Use on_vote() to ensure signature verification happens
                actions.extend(self.on_vote(vote));
            }
        }

        // Replay any early certificates.
        // IMPORTANT: We must go through on_certificate() to ensure proper signature verification.
        // Early certificates were buffered without verification, so they need to be verified now.
        if let Some((early_certs, _arrival_height)) = self.early_certificates.remove(&tx_hash) {
            tracing::debug!(tx_hash = ?tx_hash, count = early_certs.len(), "Replaying early certificates");
            for cert in early_certs {
                // Use on_certificate() to ensure signature verification happens
                actions.extend(self.on_certificate(cert));
            }
        }

        actions
    }

    /// Initiate provision broadcast for nodes we own in this transaction.
    ///
    /// This emits `FetchStateEntries` to load state from storage. When the
    /// callback arrives, `on_state_entries_fetched` will create and broadcast
    /// the actual provisions.
    fn initiate_provision_broadcast(
        &mut self,
        tx: &RoutableTransaction,
        block_height: BlockHeight,
    ) -> Vec<Action> {
        let local_shard = self.local_shard();
        let tx_hash = tx.hash();

        // Find all nodes in the transaction that we own (in our shard)
        let mut owned_nodes: Vec<_> = tx
            .declared_reads
            .iter()
            .chain(tx.declared_writes.iter())
            .filter(|&node_id| self.shard_for_node(node_id) == local_shard)
            .cloned()
            .collect();
        owned_nodes.sort();
        owned_nodes.dedup();

        if owned_nodes.is_empty() {
            return vec![];
        }

        // Find target shards (all participating shards except us)
        let target_shards: Vec<_> = self
            .all_shards_for_tx(tx)
            .into_iter()
            .filter(|&s| s != local_shard)
            .collect();

        if target_shards.is_empty() {
            return vec![];
        }

        tracing::debug!(
            tx_hash = ?tx_hash,
            owned_nodes = owned_nodes.len(),
            target_shards = ?target_shards,
            "Initiating provision broadcast - fetching state"
        );

        // Store pending broadcast info
        self.pending_provision_fetches.insert(
            tx_hash,
            PendingProvisionBroadcast {
                block_height,
                target_shards,
            },
        );

        // Request state from storage
        vec![Action::FetchStateEntries {
            tx_hash,
            nodes: owned_nodes,
        }]
    }

    /// Sign a provision.
    ///
    /// Uses the centralized `state_provision_message` for domain-separated signing.
    fn sign_provision(
        &self,
        tx_hash: &Hash,
        target_shard: ShardGroupId,
        source_shard: ShardGroupId,
        block_height: BlockHeight,
        entries: &[StateEntry],
    ) -> Signature {
        let entry_hashes: Vec<Hash> = entries.iter().map(|e| e.hash()).collect();
        let msg = hyperscale_types::state_provision_message(
            tx_hash,
            target_shard,
            source_shard,
            block_height,
            &entry_hashes,
        );
        self.signing_key.sign(&msg)
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 2: Provisioning Complete
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle provisioning complete (all source shards have reached quorum).
    ///
    /// Called when ProvisionCoordinator emits `ProvisioningComplete`, meaning
    /// all required source shards have provided a quorum of verified provisions.
    /// This triggers cross-shard execution.
    ///
    /// If the block hasn't been committed yet (i.e., tx not in pending_provisioning),
    /// we buffer the provisions and replay when the block commits.
    #[instrument(skip(self, provisions), fields(tx_hash = ?tx_hash))]
    pub fn on_provisioning_complete(
        &mut self,
        tx_hash: Hash,
        provisions: Vec<StateProvision>,
    ) -> Vec<Action> {
        let local_shard = self.local_shard();

        // Get the transaction waiting for provisions
        let Some((tx, _height)) = self.pending_provisioning.remove(&tx_hash) else {
            // Block hasn't committed yet - buffer for later
            tracing::debug!(
                tx_hash = ?tx_hash,
                shard = local_shard.0,
                "Provisioning complete before block committed, buffering"
            );
            // Track arrival height for cleanup of stale entries
            let current_height = self.committed_height;
            self.early_provisioning_complete
                .insert(tx_hash, (provisions, current_height));
            return vec![];
        };

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            provision_count = provisions.len(),
            "Provisioning complete, executing cross-shard transaction"
        );

        // Delegate execution to the runner (which batches for parallel execution)
        vec![Action::ExecuteCrossShardTransaction {
            tx_hash,
            transaction: tx,
            provisions,
        }]
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 3: Vote Aggregation
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle state vote received.
    /// Handle a state vote received from another validator.
    ///
    /// Uses deferred verification: votes are buffered until we have enough
    /// voting power to possibly reach quorum. Only then do we batch-verify
    /// all buffered votes, avoiding wasted CPU on votes we'll never use.
    ///
    /// Sender identity comes from vote.validator_id.
    #[instrument(skip(self, vote), fields(
        tx_hash = ?vote.transaction_hash,
        validator = ?vote.validator,
        success = vote.success
    ))]
    pub fn on_vote(&mut self, vote: StateVoteBlock) -> Vec<Action> {
        let tx_hash = vote.transaction_hash;
        let validator_id = vote.validator;

        // Check if we're tracking this transaction
        if !self.vote_trackers.contains_key(&tx_hash) {
            // Check if certificate already exists
            if self.state_certificates.contains_key(&tx_hash) {
                return vec![];
            }
            // Buffer for later (HashSet provides O(1) deduplication)
            // Track arrival height for cleanup of stale entries
            let current_height = self.committed_height;
            self.early_votes
                .entry(tx_hash)
                .or_insert_with(|| (HashSet::new(), current_height))
                .0
                .insert(vote);
            return vec![];
        }

        // Skip verification for our own vote - we just signed it, so we trust it.
        // This can happen when our vote is gossiped back to us via the network.
        if validator_id == self.validator_id() {
            tracing::trace!(
                tx_hash = ?tx_hash,
                "Skipping verification for own vote"
            );
            return self.handle_verified_vote(vote);
        }

        // Check if we've already verified this exact vote (by tx_hash + validator).
        // This happens when votes are gossiped multiple times or during retries.
        // Avoids redundant crypto work.
        if self
            .verified_state_votes
            .contains_key(&(tx_hash, validator_id))
        {
            tracing::trace!(
                tx_hash = ?tx_hash,
                validator = validator_id.0,
                "State vote already verified, skipping re-verification"
            );
            return self.handle_verified_vote(vote);
        }

        // Get public key for signature verification
        let Some(public_key) = self.public_key(validator_id) else {
            tracing::warn!(
                tx_hash = ?tx_hash,
                validator = validator_id.0,
                "Unknown validator for state vote"
            );
            return vec![];
        };

        // Get voting power
        let voting_power = self.voting_power(validator_id);

        // Get the tracker and buffer the vote
        let tracker = self.vote_trackers.get_mut(&tx_hash).unwrap();

        // Check if already seen (dedup within tracker)
        if tracker.has_seen_validator(validator_id) {
            return vec![];
        }

        // Buffer the unverified vote
        tracker.buffer_unverified_vote(vote, public_key, voting_power);

        // Check if we should trigger batch verification
        self.maybe_trigger_state_vote_verification(tx_hash)
    }

    /// Check if we have enough buffered votes to trigger verification.
    fn maybe_trigger_state_vote_verification(&mut self, tx_hash: Hash) -> Vec<Action> {
        let Some(tracker) = self.vote_trackers.get_mut(&tx_hash) else {
            return vec![];
        };

        if !tracker.should_trigger_verification() {
            return vec![];
        }

        // Take the unverified votes for batch verification
        let votes = tracker.take_unverified_votes();

        if votes.is_empty() {
            return vec![];
        }

        tracing::debug!(
            tx_hash = ?tx_hash,
            vote_count = votes.len(),
            "Triggering batch state vote verification (have enough for quorum)"
        );

        vec![Action::VerifyAndAggregateStateVotes { tx_hash, votes }]
    }

    /// Handle batch state vote verification result.
    ///
    /// Callback from `Action::VerifyAndAggregateStateVotes`.
    #[instrument(skip(self, verified_votes), fields(
        tx_hash = ?tx_hash,
        verified_count = verified_votes.len()
    ))]
    pub fn on_state_votes_verified(
        &mut self,
        tx_hash: Hash,
        verified_votes: Vec<(StateVoteBlock, u64)>,
    ) -> Vec<Action> {
        let Some(tracker) = self.vote_trackers.get_mut(&tx_hash) else {
            tracing::debug!(
                tx_hash = ?tx_hash,
                "State votes verified but no tracker found (tx cleaned up)"
            );
            return vec![];
        };

        // Clear the pending verification flag
        tracker.on_verification_complete();

        if verified_votes.is_empty() {
            tracing::warn!(
                tx_hash = ?tx_hash,
                "All state votes in batch failed verification"
            );
            // Check if more votes arrived while we were verifying
            return self.maybe_trigger_state_vote_verification(tx_hash);
        }

        tracing::debug!(
            tx_hash = ?tx_hash,
            verified_count = verified_votes.len(),
            "Batch state vote verification complete"
        );

        // Add all verified votes to the tracker and cache them
        let mut actions = Vec::new();
        for (vote, voting_power) in verified_votes {
            let validator_id = vote.validator;

            // Cache the verified vote
            self.verified_state_votes.insert((tx_hash, validator_id), 0);
            self.verified_votes_by_tx
                .entry(tx_hash)
                .or_default()
                .insert(validator_id);

            // Add to tracker as verified
            if let Some(tracker) = self.vote_trackers.get_mut(&tx_hash) {
                tracker.add_verified_vote(vote, voting_power);
            }
        }

        // Check for quorum after adding all verified votes
        actions.extend(self.check_vote_quorum(tx_hash));

        // Check if more votes arrived while we were verifying
        actions.extend(self.maybe_trigger_state_vote_verification(tx_hash));

        actions
    }

    /// Handle a verified vote (own vote or already-verified vote).
    ///
    /// Adds the vote to the tracker and checks for quorum.
    fn handle_verified_vote(&mut self, vote: StateVoteBlock) -> Vec<Action> {
        let tx_hash = vote.transaction_hash;
        let voting_power = self.voting_power(vote.validator);

        let Some(tracker) = self.vote_trackers.get_mut(&tx_hash) else {
            return vec![];
        };

        // Mark as seen to prevent re-buffering if vote arrives again
        let validator_id = vote.validator;
        if !tracker.has_seen_validator(validator_id) {
            // We need to mark it as seen even though we're adding it directly
            // Use a dummy public key since we won't actually verify
            // Actually, we should track this differently - let's just add to verified_state_votes
            self.verified_state_votes.insert((tx_hash, validator_id), 0);
            self.verified_votes_by_tx
                .entry(tx_hash)
                .or_default()
                .insert(validator_id);
        }

        tracker.add_verified_vote(vote, voting_power);

        self.check_vote_quorum(tx_hash)
    }

    /// Check if quorum is reached for a transaction's votes.
    ///
    /// If quorum is reached, triggers BLS signature aggregation.
    fn check_vote_quorum(&mut self, tx_hash: Hash) -> Vec<Action> {
        let local_shard = self.local_shard();

        let Some(tracker) = self.vote_trackers.get_mut(&tx_hash) else {
            return vec![];
        };

        // Check for quorum
        let Some((merkle_root, total_power)) = tracker.check_quorum() else {
            return vec![];
        };

        // Extract data from tracker - use take_votes_for_root to avoid cloning
        let votes = tracker.take_votes_for_root(&merkle_root);
        let read_nodes = tracker.read_nodes().to_vec();
        let participating_shards = tracker.participating_shards().to_vec();

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            merkle_root = ?merkle_root,
            votes = votes.len(),
            power = total_power,
            "Vote quorum reached - delegating BLS aggregation"
        );

        // Store pending aggregation state for callback
        self.pending_cert_aggregations.insert(
            tx_hash,
            PendingCertificateAggregation {
                participating_shards,
            },
        );

        // Delegate BLS signature aggregation to crypto pool
        let committee_size = self.committee().len();

        // Remove vote tracker (we've extracted what we need)
        self.vote_trackers.remove(&tx_hash);

        vec![Action::AggregateStateCertificate {
            tx_hash,
            shard: local_shard,
            merkle_root,
            votes,
            read_nodes,
            voting_power: VotePower(total_power),
            committee_size,
        }]
    }

    /// Handle state certificate aggregation completed.
    ///
    /// Callback from `Action::AggregateStateCertificate`. The crypto pool has
    /// finished BLS signature aggregation and produced the certificate.
    #[instrument(skip(self, certificate), fields(
        tx_hash = ?tx_hash,
        shard = certificate.shard_group_id.0,
        success = certificate.success
    ))]
    fn on_state_certificate_aggregated(
        &mut self,
        tx_hash: Hash,
        certificate: StateCertificate,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // Get pending aggregation state
        let Some(pending) = self.pending_cert_aggregations.remove(&tx_hash) else {
            tracing::warn!(
                tx_hash = ?tx_hash,
                "Received certificate aggregation callback but no pending aggregation found"
            );
            return actions;
        };

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = certificate.shard_group_id.0,
            participating_shards = pending.participating_shards.len(),
            "State certificate aggregation complete"
        );

        // Store certificate
        self.state_certificates.insert(tx_hash, certificate.clone());

        // Broadcast certificate to all participating shards (runner handles batching)
        for target_shard in pending.participating_shards {
            actions.push(Action::BroadcastStateCertificate {
                shard: target_shard,
                certificate: certificate.clone(),
            });
        }

        // Handle our own certificate
        actions.extend(self.handle_certificate_internal(certificate));

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 4: Finalization
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle state certificate received.
    ///
    /// Delegates signature verification to the runner before processing.
    /// Handle a state certificate received from another validator.
    #[instrument(skip(self, cert), fields(
        tx_hash = ?cert.transaction_hash,
        shard = cert.shard_group_id.0,
        success = cert.success
    ))]
    pub fn on_certificate(&mut self, cert: StateCertificate) -> Vec<Action> {
        let tx_hash = cert.transaction_hash;
        let shard = cert.shard_group_id;

        // Check if we're tracking this transaction
        if !self.certificate_trackers.contains_key(&tx_hash) {
            // Check if already finalized
            if self.finalized_certificates.contains_key(&tx_hash) {
                return vec![];
            }
            // Buffer for later, track arrival height for cleanup of stale entries
            let current_height = self.committed_height;
            self.early_certificates
                .entry(tx_hash)
                .or_insert_with(|| (Vec::new(), current_height))
                .0
                .push(cert);
            return vec![];
        }

        // Get public keys for the signers in the certificate's source shard
        let committee = self.topology.committee_for_shard(shard);
        let public_keys: Vec<PublicKey> = committee
            .iter()
            .filter_map(|&vid| self.topology.public_key(vid))
            .collect();

        if public_keys.len() != committee.len() {
            tracing::warn!(
                tx_hash = ?tx_hash,
                shard = shard.0,
                "Could not resolve all public keys for certificate verification"
            );
            return vec![];
        }

        // Track pending verification
        self.pending_cert_verifications.insert(
            (tx_hash, shard),
            PendingCertificateVerification {
                certificate: cert.clone(),
            },
        );
        // Update reverse index for O(k) cleanup
        self.pending_verifications_by_tx
            .entry(tx_hash)
            .or_default()
            .insert(PendingVerificationKey::Certificate(shard));

        // Delegate signature verification to runner
        vec![Action::VerifyStateCertificateSignature {
            certificate: cert,
            public_keys,
        }]
    }

    /// Handle state certificate signature verification result.
    #[instrument(skip(self, certificate), fields(
        tx_hash = ?certificate.transaction_hash,
        shard = certificate.shard_group_id.0,
        valid = valid
    ))]
    pub fn on_certificate_verified(
        &mut self,
        certificate: StateCertificate,
        valid: bool,
    ) -> Vec<Action> {
        let tx_hash = certificate.transaction_hash;
        let shard = certificate.shard_group_id;

        // Check if this is a fetched certificate verification
        if self
            .pending_fetched_cert_verifications
            .contains_key(&tx_hash)
        {
            return self.handle_fetched_cert_verified(tx_hash, shard, valid);
        }

        // Otherwise, it's a gossiped certificate for 2PC flow
        self.pending_cert_verifications.remove(&(tx_hash, shard));
        // Update reverse index
        if let Some(keys) = self.pending_verifications_by_tx.get_mut(&tx_hash) {
            keys.remove(&PendingVerificationKey::Certificate(shard));
        }

        if !valid {
            tracing::warn!(
                tx_hash = ?tx_hash,
                shard = shard.0,
                "Invalid state certificate signature"
            );
            return vec![];
        }

        self.handle_certificate_internal(certificate)
    }

    /// Handle verification result for a fetched certificate's StateCertificate.
    fn handle_fetched_cert_verified(
        &mut self,
        tx_hash: Hash,
        shard: ShardGroupId,
        valid: bool,
    ) -> Vec<Action> {
        let Some(pending) = self.pending_fetched_cert_verifications.get_mut(&tx_hash) else {
            return vec![];
        };

        // Remove this shard from pending
        pending.pending_shards.remove(&shard);

        if !valid {
            tracing::warn!(
                tx_hash = ?tx_hash,
                shard = shard.0,
                "Invalid fetched certificate - StateCertificate signature verification failed"
            );
            pending.has_failed = true;
        }

        // Check if all shards are verified
        if !pending.pending_shards.is_empty() {
            // Still waiting for more verifications
            return vec![];
        }

        // All shards verified - remove from pending and emit result
        let pending = self
            .pending_fetched_cert_verifications
            .remove(&tx_hash)
            .unwrap();

        if pending.has_failed {
            tracing::warn!(
                tx_hash = ?tx_hash,
                block_hash = ?pending.block_hash,
                "Fetched certificate failed verification - not adding to pending block"
            );
            return vec![];
        }

        tracing::debug!(
            tx_hash = ?tx_hash,
            block_hash = ?pending.block_hash,
            "Fetched certificate verified successfully"
        );

        // Emit event so NodeStateMachine can route to BFT
        vec![Action::EnqueueInternal {
            event: Event::FetchedCertificateVerified {
                block_hash: pending.block_hash,
                certificate: pending.certificate,
            },
        }]
    }

    /// Verify a fetched TransactionCertificate by checking all embedded StateCertificates.
    ///
    /// Each StateCertificate is verified against its shard's committee public keys.
    /// When all verify successfully, a FetchedCertificateVerified event is emitted.
    pub fn verify_fetched_certificate(
        &mut self,
        block_hash: Hash,
        certificate: TransactionCertificate,
    ) -> Vec<Action> {
        let tx_hash = certificate.transaction_hash;
        let mut actions = Vec::new();

        // Collect all shards that need verification
        let pending_shards: HashSet<ShardGroupId> =
            certificate.shard_proofs.keys().copied().collect();

        if pending_shards.is_empty() {
            // No proofs to verify (empty certificate) - accept it directly
            tracing::debug!(
                tx_hash = ?tx_hash,
                block_hash = ?block_hash,
                "Fetched certificate has no shard proofs - accepting directly"
            );
            return vec![Action::EnqueueInternal {
                event: Event::FetchedCertificateVerified {
                    block_hash,
                    certificate,
                },
            }];
        }

        // Track the pending verification
        self.pending_fetched_cert_verifications.insert(
            tx_hash,
            PendingFetchedCertificateVerification {
                certificate: certificate.clone(),
                block_hash,
                pending_shards: pending_shards.clone(),
                has_failed: false,
            },
        );

        // Emit verification action for each embedded StateCertificate
        for (shard_id, state_cert) in &certificate.shard_proofs {
            // Get public keys for this shard's committee
            let committee = self.topology.committee_for_shard(*shard_id);
            let public_keys: Vec<PublicKey> = committee
                .iter()
                .filter_map(|&vid| self.topology.public_key(vid))
                .collect();

            if public_keys.len() != committee.len() {
                tracing::warn!(
                    tx_hash = ?tx_hash,
                    shard = shard_id.0,
                    "Could not resolve all public keys for fetched certificate verification"
                );
                // Mark as failed but continue - other verifications may still succeed
                if let Some(pending) = self.pending_fetched_cert_verifications.get_mut(&tx_hash) {
                    pending.has_failed = true;
                    pending.pending_shards.remove(shard_id);
                }
                continue;
            }

            actions.push(Action::VerifyStateCertificateSignature {
                certificate: state_cert.clone(),
                public_keys,
            });
        }

        actions
    }

    /// Internal certificate handling (assumes tracking is active).
    #[instrument(level = "debug", skip(self, cert), fields(
        tx_hash = %cert.transaction_hash,
        cert_shard = cert.shard_group_id.0,
    ))]
    fn handle_certificate_internal(&mut self, cert: StateCertificate) -> Vec<Action> {
        let mut actions = Vec::new();
        let tx_hash = cert.transaction_hash;
        let cert_shard = cert.shard_group_id;

        let local_shard = self.local_shard();
        let Some(tracker) = self.certificate_trackers.get_mut(&tx_hash) else {
            tracing::debug!(
                tx_hash = ?tx_hash,
                cert_shard = cert_shard.0,
                local_shard = local_shard.0,
                "No certificate tracker for tx, ignoring certificate"
            );
            return actions;
        };

        let complete = tracker.add_certificate(cert);

        if complete {
            tracing::debug!(
                tx_hash = ?tx_hash,
                shards = tracker.certificate_count(),
                local_shard = local_shard.0,
                "All certificates collected, creating TransactionCertificate"
            );

            // Create transaction certificate
            if let Some(tx_cert) = tracker.create_tx_certificate() {
                // Determine if transaction was accepted
                let accepted = tx_cert.decision == TransactionDecision::Accept;

                tracing::debug!(
                    tx_hash = ?tx_hash,
                    accepted = accepted,
                    local_shard = local_shard.0,
                    "TransactionCertificate created successfully"
                );

                // Eagerly persist certificate so peers can fetch it before block commit.
                // This is idempotent - storing twice (here and in put_block_denormalized) is safe.
                actions.push(Action::PersistTransactionCertificate {
                    certificate: tx_cert.clone(),
                });

                self.finalized_certificates
                    .insert(tx_hash, Arc::new(tx_cert));

                // Notify mempool that transaction execution is complete
                actions.push(Action::EnqueueInternal {
                    event: Event::TransactionExecuted { tx_hash, accepted },
                });
            } else {
                tracing::warn!(
                    tx_hash = ?tx_hash,
                    local_shard = local_shard.0,
                    "Failed to create TransactionCertificate despite all certs collected"
                );
            }

            // Remove tracker
            self.certificate_trackers.remove(&tx_hash);
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Query Methods
    // ═══════════════════════════════════════════════════════════════════════════

    /// Get finalized certificates for block inclusion.
    pub fn get_finalized_certificates(&self) -> Vec<Arc<TransactionCertificate>> {
        self.finalized_certificates.values().cloned().collect()
    }

    /// Get finalized certificates as a HashMap for block validation.
    pub fn finalized_certificates_by_hash(
        &self,
    ) -> std::collections::HashMap<Hash, Arc<TransactionCertificate>> {
        self.finalized_certificates
            .iter()
            .map(|(h, c)| (*h, Arc::clone(c)))
            .collect()
    }

    /// Get a single finalized certificate by transaction hash.
    ///
    /// Checks both the pending finalized certificates (not yet committed) and
    /// the recently committed certificates cache (for peer fetch requests).
    pub fn get_finalized_certificate(&self, tx_hash: &Hash) -> Option<Arc<TransactionCertificate>> {
        // First check pending finalized certificates
        if let Some(cert) = self.finalized_certificates.get(tx_hash) {
            return Some(cert.clone());
        }
        // Fall back to recently committed certificates cache
        self.recently_committed_certificates
            .get(tx_hash)
            .map(|(cert, _)| cert.clone())
    }

    /// Remove a finalized certificate (after it's been included in a block).
    ///
    /// Moves the certificate to the recently_committed_certificates cache
    /// so that slow peers can still fetch it. The cache is pruned after
    /// CERTIFICATE_RETENTION_BLOCKS.
    ///
    /// Also cleans up the verified state vote cache for this transaction
    /// since we no longer need to track verification state after finalization.
    pub fn remove_finalized_certificate(&mut self, tx_hash: &Hash, commit_height: u64) {
        // Clean up verified vote cache using reverse index for O(k) instead of O(n)
        if let Some(validators) = self.verified_votes_by_tx.remove(tx_hash) {
            for vid in validators {
                self.verified_state_votes.remove(&(*tx_hash, vid));
            }
        }

        // Move certificate to recently_committed cache instead of discarding
        if let Some(cert) = self.finalized_certificates.remove(tx_hash) {
            self.recently_committed_certificates
                .insert(*tx_hash, (cert, commit_height));
        }

        // Clean up all transaction tracking state now that it's finalized.
        // This is the same cleanup done by cleanup_transaction() for aborts/deferrals,
        // but we need to do it here for successful completions too.
        self.pending_provisioning.remove(tx_hash);
        self.pending_provision_fetches.remove(tx_hash);
        self.vote_trackers.remove(tx_hash);
        self.state_certificates.remove(tx_hash);
        self.certificate_trackers.remove(tx_hash);
        self.early_provisioning_complete.remove(tx_hash);
        self.early_votes.remove(tx_hash);
        self.early_certificates.remove(tx_hash);

        // Pending verifications cleanup using reverse index for O(k) instead of O(n)
        if let Some(keys) = self.pending_verifications_by_tx.remove(tx_hash) {
            for key in keys {
                match key {
                    PendingVerificationKey::Certificate(shard) => {
                        self.pending_cert_verifications.remove(&(*tx_hash, shard));
                    }
                }
            }
        }
        self.pending_fetched_cert_verifications.remove(tx_hash);
        self.pending_cert_aggregations.remove(tx_hash);

        // Update committed height and prune old entries
        if commit_height > self.committed_height {
            self.committed_height = commit_height;
            self.prune_recently_committed_certificates();
        }
    }

    /// Prune recently committed certificates older than CERTIFICATE_RETENTION_BLOCKS.
    fn prune_recently_committed_certificates(&mut self) {
        let cutoff = self
            .committed_height
            .saturating_sub(CERTIFICATE_RETENTION_BLOCKS);
        self.recently_committed_certificates
            .retain(|_, (_, height)| *height > cutoff);
    }

    /// Check if a transaction has been executed.
    pub fn is_executed(&self, tx_hash: &Hash) -> bool {
        self.executed_txs.contains_key(tx_hash)
    }

    /// Prune old executed transaction entries to prevent unbounded growth.
    fn prune_executed_txs(&mut self) {
        let cutoff = self
            .committed_height
            .saturating_sub(EXECUTED_TX_RETENTION_BLOCKS);
        self.executed_txs.retain(|_, height| *height > cutoff);
    }

    /// Prune stale early arrival entries to prevent unbounded growth.
    ///
    /// Early arrivals (votes, certificates, and provisioning events that arrive
    /// before the transaction is being tracked) are kept for a generous window
    /// to allow for block reordering and sync delays. After
    /// EARLY_ARRIVAL_RETENTION_BLOCKS, they are considered stale and removed.
    fn prune_early_arrivals(&mut self) {
        let cutoff = self
            .committed_height
            .saturating_sub(EARLY_ARRIVAL_RETENTION_BLOCKS);

        let before_provisions = self.early_provisioning_complete.len();
        self.early_provisioning_complete
            .retain(|_, (_, arrival_height)| *arrival_height > cutoff);
        let pruned_provisions = before_provisions - self.early_provisioning_complete.len();

        let before_votes = self.early_votes.len();
        self.early_votes
            .retain(|_, (_, arrival_height)| *arrival_height > cutoff);
        let pruned_votes = before_votes - self.early_votes.len();

        let before_certs = self.early_certificates.len();
        self.early_certificates
            .retain(|_, (_, arrival_height)| *arrival_height > cutoff);
        let pruned_certs = before_certs - self.early_certificates.len();

        if pruned_provisions > 0 || pruned_votes > 0 || pruned_certs > 0 {
            tracing::debug!(
                pruned_provisions,
                pruned_votes,
                pruned_certs,
                cutoff_height = cutoff,
                "Pruned stale early arrivals"
            );
        }
    }

    /// Prune old verified vote cache entries to prevent unbounded growth.
    ///
    /// The verified vote cache stores signatures we've already verified to avoid
    /// re-verification. Entries older than VERIFIED_VOTE_RETENTION_BLOCKS are
    /// cleaned up regardless of whether the transaction has finalized.
    fn prune_verified_votes(&mut self) {
        let cutoff = self
            .committed_height
            .saturating_sub(VERIFIED_VOTE_RETENTION_BLOCKS);

        // Collect tx_hashes that have all votes older than cutoff
        let mut tx_hashes_to_clean = Vec::new();
        for (tx_hash, validators) in &self.verified_votes_by_tx {
            // Check if all votes for this tx are old
            let all_old = validators.iter().all(|vid| {
                self.verified_state_votes
                    .get(&(*tx_hash, *vid))
                    .map(|h| *h <= cutoff)
                    .unwrap_or(true)
            });
            if all_old {
                tx_hashes_to_clean.push(*tx_hash);
            }
        }

        // Clean up old entries
        let mut pruned_count = 0;
        for tx_hash in tx_hashes_to_clean {
            if let Some(validators) = self.verified_votes_by_tx.remove(&tx_hash) {
                for vid in validators {
                    if self.verified_state_votes.remove(&(tx_hash, vid)).is_some() {
                        pruned_count += 1;
                    }
                }
            }
        }

        if pruned_count > 0 {
            tracing::debug!(
                pruned_count,
                cutoff_height = cutoff,
                "Pruned old verified vote cache entries"
            );
        }
    }

    /// Check if a transaction is finalized.
    pub fn is_finalized(&self, tx_hash: &Hash) -> bool {
        self.finalized_certificates.contains_key(tx_hash)
    }

    /// Check if we're waiting for provisioning to complete for a transaction.
    ///
    /// Note: Actual provision tracking is handled by ProvisionCoordinator.
    pub fn is_awaiting_provisioning(&self, tx_hash: &Hash) -> bool {
        self.pending_provisioning.contains_key(tx_hash)
    }

    /// Check if we're tracking votes for a transaction.
    pub fn is_tracking_votes(&self, tx_hash: &Hash) -> bool {
        self.vote_trackers.contains_key(tx_hash)
    }

    /// Check if we have a state certificate for a transaction.
    pub fn has_state_certificate(&self, tx_hash: &Hash) -> bool {
        self.state_certificates.contains_key(tx_hash)
    }

    /// Get debug info about certificate tracking state for a transaction.
    pub fn certificate_tracking_debug(&self, tx_hash: &Hash) -> String {
        let has_vote_tracker = self.vote_trackers.contains_key(tx_hash);
        let has_state_cert = self.state_certificates.contains_key(tx_hash);
        let has_cert_tracker = self.certificate_trackers.contains_key(tx_hash);
        let early_cert_count = self
            .early_certificates
            .get(tx_hash)
            .map(|(v, _)| v.len())
            .unwrap_or(0);

        let cert_tracker_info = if let Some(tracker) = self.certificate_trackers.get(tx_hash) {
            format!(
                "{}/{} certs",
                tracker.certificate_count(),
                tracker.expected_count()
            )
        } else {
            "no tracker".to_string()
        };

        format!(
            "vote_tracker={}, state_cert={}, cert_tracker={} ({}), early_certs={}",
            has_vote_tracker, has_state_cert, has_cert_tracker, cert_tracker_info, early_cert_count
        )
    }

    /// Cleanup all tracking state for a deferred or aborted transaction.
    ///
    /// Called when a transaction is deferred (livelock cycle) or aborted (timeout).
    /// This releases all resources associated with the transaction so it doesn't
    /// continue consuming memory or processing.
    pub fn cleanup_transaction(&mut self, tx_hash: &Hash) {
        // If the transaction is already finalized, don't clean it up.
        // The abort was proposed before finalization completed, but finalization won.
        if self.finalized_certificates.contains_key(tx_hash) {
            tracing::debug!(
                tx_hash = ?tx_hash,
                "Transaction already finalized, skipping cleanup"
            );
            return;
        }

        // Remove from executed set so retry can be processed
        self.executed_txs.remove(tx_hash);

        // Phase 1-2: Provisioning cleanup
        // Note: Provision tracking is handled by ProvisionCoordinator
        self.pending_provisioning.remove(tx_hash);
        self.pending_provision_fetches.remove(tx_hash);

        // Phase 3-4: Vote cleanup
        self.vote_trackers.remove(tx_hash);
        self.state_certificates.remove(tx_hash);

        // Phase 5: Certificate cleanup
        self.certificate_trackers.remove(tx_hash);

        // Early arrivals cleanup
        self.early_provisioning_complete.remove(tx_hash);
        self.early_votes.remove(tx_hash);
        self.early_certificates.remove(tx_hash);

        // Pending verifications cleanup using reverse index for O(k) instead of O(n)
        // Note: Provision signature verification is handled by ProvisionCoordinator
        if let Some(keys) = self.pending_verifications_by_tx.remove(tx_hash) {
            for key in keys {
                match key {
                    PendingVerificationKey::Certificate(shard) => {
                        self.pending_cert_verifications.remove(&(*tx_hash, shard));
                    }
                }
            }
        }

        // Verified vote cache cleanup using reverse index for O(k) instead of O(n)
        if let Some(validators) = self.verified_votes_by_tx.remove(tx_hash) {
            for vid in validators {
                self.verified_state_votes.remove(&(*tx_hash, vid));
            }
        }

        tracing::debug!(
            tx_hash = %tx_hash,
            "Cleaned up execution state for deferred/aborted transaction"
        );
    }

    /// Cancel local certificate building for a transaction.
    ///
    /// Called when we receive a verified certificate from another node (via fetch or gossip)
    /// instead of building our own. This cleans up all local certificate building state:
    /// certificate tracking, vote aggregation, our own StateCertificate, and pending verifications.
    ///
    /// Note: This keeps `executed_txs` for deduplication.
    pub fn cancel_certificate_building(&mut self, tx_hash: &Hash) {
        let had_tracker = self.certificate_trackers.remove(tx_hash).is_some();
        let had_early = self.early_certificates.remove(tx_hash).is_some();

        // Clean up vote aggregation - we don't need to build our own StateCertificate
        let had_vote_tracker = self.vote_trackers.remove(tx_hash).is_some();
        let had_aggregation = self.pending_cert_aggregations.remove(tx_hash).is_some();
        self.early_votes.remove(tx_hash);

        // Clean up our local StateCertificate - peers can't request it, and the
        // external certificate we received contains all the StateCertificates we need
        self.state_certificates.remove(tx_hash);

        // Clean up pending fetched certificate verifications for this tx
        self.pending_fetched_cert_verifications.remove(tx_hash);

        // Clean up pending verifications using reverse index
        let mut removed_cert_count = 0;
        if let Some(keys) = self.pending_verifications_by_tx.get_mut(tx_hash) {
            let keys_to_remove: Vec<_> = keys.iter().cloned().collect();
            for key in keys_to_remove {
                match key {
                    PendingVerificationKey::Certificate(shard) => {
                        self.pending_cert_verifications.remove(&(*tx_hash, shard));
                        keys.remove(&key);
                        removed_cert_count += 1;
                    }
                }
            }
        }

        // Clean up verified votes cache
        if let Some(validators) = self.verified_votes_by_tx.remove(tx_hash) {
            for vid in validators {
                self.verified_state_votes.remove(&(*tx_hash, vid));
            }
        }

        if had_tracker || had_early || had_vote_tracker || had_aggregation || removed_cert_count > 0
        {
            tracing::debug!(
                tx_hash = %tx_hash,
                had_cert_tracker = had_tracker,
                had_vote_tracker = had_vote_tracker,
                had_aggregation = had_aggregation,
                removed_cert_verifications = removed_cert_count,
                "Cancelled local certificate building - using external certificate"
            );
        }
    }

    /// Add a verified certificate received from gossip or fetch.
    ///
    /// Called after a TransactionCertificate from another validator has been verified.
    /// This adds it to finalized_certificates so it's available for block inclusion,
    /// without going through the normal vote aggregation and certificate tracking flow.
    pub fn add_verified_certificate(&mut self, certificate: TransactionCertificate) {
        let tx_hash = certificate.transaction_hash;

        // Check if already finalized
        if self.finalized_certificates.contains_key(&tx_hash) {
            tracing::debug!(
                tx_hash = ?tx_hash,
                "Certificate already finalized, skipping add"
            );
            return;
        }

        tracing::debug!(
            tx_hash = ?tx_hash,
            decision = ?certificate.decision,
            shards = certificate.shard_proofs.len(),
            "Adding verified certificate from gossip"
        );

        self.finalized_certificates
            .insert(tx_hash, Arc::new(certificate));
    }

    /// Handle state entries fetched from storage.
    ///
    /// This is called when the runner completes a `FetchStateEntries` action
    /// and returns the state entries (with pre-computed storage keys) for
    /// cross-shard provisioning.
    #[instrument(skip(self, entries), fields(
        tx_hash = ?tx_hash,
        entry_count = entries.len(),
        sign_us = tracing::field::Empty,
    ))]
    pub fn on_state_entries_fetched(
        &mut self,
        tx_hash: Hash,
        entries: Vec<StateEntry>,
    ) -> Vec<Action> {
        debug!(
            tx_hash = ?tx_hash,
            entries = entries.len(),
            "State entries fetched from storage"
        );

        // Get the pending broadcast info
        let Some(pending) = self.pending_provision_fetches.remove(&tx_hash) else {
            tracing::warn!(
                tx_hash = ?tx_hash,
                "State entries fetched but no pending provision broadcast"
            );
            return vec![];
        };

        let mut actions = Vec::new();
        let local_shard = self.local_shard();

        // Wrap entries in Arc once for efficient sharing across multiple target shards.
        // This avoids cloning the potentially large Vec<StateEntry> for each broadcast.
        let entries = Arc::new(entries);

        // Track total signing time for all provisions
        let mut total_sign_us = 0u64;

        // Create and broadcast provisions to each target shard
        for target_shard in pending.target_shards {
            let sign_start = std::time::Instant::now();
            let signature = self.sign_provision(
                &tx_hash,
                target_shard,
                local_shard,
                pending.block_height,
                &entries,
            );
            total_sign_us += sign_start.elapsed().as_micros() as u64;

            let provision = StateProvision {
                transaction_hash: tx_hash,
                target_shard,
                source_shard: local_shard,
                block_height: pending.block_height,
                entries: Arc::clone(&entries),
                validator_id: self.validator_id(),
                signature,
            };

            actions.push(Action::BroadcastStateProvision {
                shard: target_shard,
                provision,
            });

            tracing::debug!(
                tx_hash = ?tx_hash,
                target_shard = target_shard.0,
                entries = entries.len(),
                "Broadcasting provision with state entries"
            );
        }

        tracing::Span::current().record("sign_us", total_sign_us);
        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Speculative Execution
    // ═══════════════════════════════════════════════════════════════════════════

    /// Notify that a view change (round timeout) occurred at the given height.
    ///
    /// Speculation will be paused for a few rounds to avoid wasted work,
    /// since blocks proposed during instability may not commit.
    #[instrument(skip(self), fields(height = height))]
    pub fn on_view_change(&mut self, height: u64) {
        tracing::debug!(
            height,
            cooldown_rounds = self.view_change_cooldown_rounds,
            "View change detected - pausing speculation"
        );
        self.last_view_change_height = height;

        // Clear in-flight speculation - those results are likely stale
        self.speculative_in_flight_txs.clear();
        self.pending_speculative_executions.clear();
    }

    /// Check if we should speculatively execute transactions at the given height.
    ///
    /// Returns false if:
    /// 1. Memory limit exceeded (too many in-flight + cached txs)
    /// 2. Within cooldown period after a view change
    pub fn should_speculative_execute(&self, height: u64) -> bool {
        // Don't speculate within cooldown period after view change
        if height <= self.last_view_change_height + self.view_change_cooldown_rounds {
            return false;
        }

        // Memory limit - don't cache unlimited results
        // In-flight txs will become cached results, so count both
        let total_speculative =
            self.speculative_results.len() + self.speculative_in_flight_txs.len();
        total_speculative < self.speculative_max_txs
    }

    /// Trigger speculative execution for single-shard transactions in a block.
    ///
    /// Called when a block header is received, before the block commits.
    /// Returns an action to execute the transactions speculatively.
    pub fn trigger_speculative_execution(
        &mut self,
        block_hash: Hash,
        height: u64,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Vec<Action> {
        if !self.should_speculative_execute(height) {
            let in_cooldown =
                height <= self.last_view_change_height + self.view_change_cooldown_rounds;
            tracing::debug!(
                block_hash = ?block_hash,
                height,
                in_flight_txs = self.speculative_in_flight_txs.len(),
                cache_size = self.speculative_results.len(),
                in_cooldown,
                last_view_change = self.last_view_change_height,
                "Skipping speculative execution"
            );
            return vec![];
        }

        // Filter to single-shard transactions that haven't been executed, cached, or in-flight
        let single_shard_txs: Vec<_> = transactions
            .into_iter()
            .filter(|tx| self.is_single_shard(tx))
            .filter(|tx| !self.speculative_results.contains_key(&tx.hash()))
            .filter(|tx| !self.speculative_in_flight_txs.contains(&tx.hash()))
            .filter(|tx| !self.executed_txs.contains_key(&tx.hash()))
            .collect();

        if single_shard_txs.is_empty() {
            return vec![];
        }

        tracing::info!(
            block_hash = ?block_hash,
            tx_count = single_shard_txs.len(),
            "SPECULATIVE TRIGGER: Starting speculative execution"
        );

        // Track in-flight txs (no block limit - only memory matters)
        for tx in &single_shard_txs {
            self.speculative_in_flight_txs.insert(tx.hash());
        }

        // Store transactions so we can get declared_reads when execution completes
        self.pending_speculative_executions
            .insert(block_hash, single_shard_txs.clone());

        // Track metrics
        self.speculative_started_count += single_shard_txs.len() as u64;

        vec![Action::SpeculativeExecute {
            block_hash,
            transactions: single_shard_txs,
        }]
    }

    /// Handle speculative execution completion callback.
    ///
    /// Caches the results for use when the block commits. If the block has already
    /// committed and is waiting for this speculation, the result is processed
    /// immediately via the normal execution path.
    #[instrument(skip(self, results), fields(block_hash = ?block_hash, result_count = results.len()))]
    pub fn on_speculative_execution_complete(
        &mut self,
        block_hash: Hash,
        results: Vec<(Hash, ExecutionResult)>,
    ) -> Vec<Action> {
        tracing::info!(
            block_hash = ?block_hash,
            result_count = results.len(),
            "SPECULATIVE COMPLETE: Received speculative execution results"
        );

        let mut actions = Vec::new();

        // Get the transactions we were executing to retrieve their declared_reads
        let transactions = self
            .pending_speculative_executions
            .remove(&block_hash)
            .unwrap_or_default();

        // Build a map from tx_hash to transaction for quick lookup
        let tx_map: HashMap<Hash, &Arc<RoutableTransaction>> =
            transactions.iter().map(|tx| (tx.hash(), tx)).collect();

        // Process results - either use immediately if committed, or cache for later
        for (tx_hash, result) in results {
            // Remove from in-flight tracking
            self.speculative_in_flight_txs.remove(&tx_hash);

            // Check if this tx already committed and is waiting for speculation
            if let Some((committed_block_hash, _tx)) =
                self.committed_awaiting_speculation.remove(&tx_hash)
            {
                // Block already committed - use result immediately
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    committed_block_hash = ?committed_block_hash,
                    "SPECULATIVE LATE HIT: Using speculative result for already-committed tx"
                );
                self.record_speculative_late_hit();
                // Runner will sign this result and send StateVoteReceived
                actions.push(Action::SignExecutionResults {
                    results: vec![result],
                });
                continue;
            }

            // Skip if already executed through some other path
            if self.executed_txs.contains_key(&tx_hash) {
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    "Discarding speculative result - tx already executed"
                );
                continue;
            }

            // Get the read set from the transaction's declared_reads
            let read_set: HashSet<NodeId> = tx_map
                .get(&tx_hash)
                .map(|tx| tx.declared_reads.iter().cloned().collect())
                .unwrap_or_default();

            // Index for fast invalidation
            for node_id in &read_set {
                self.speculative_reads_index
                    .entry(*node_id)
                    .or_default()
                    .insert(tx_hash);
            }

            // Cache the result for later use when block commits
            self.speculative_results.insert(
                tx_hash,
                SpeculativeResult {
                    result,
                    read_set,
                    created_at: self.now,
                },
            );

            tracing::debug!(
                tx_hash = ?tx_hash,
                block_hash = ?block_hash,
                "Cached speculative execution result"
            );
        }

        actions
    }

    /// Invalidate speculative results that conflict with a committed certificate.
    ///
    /// Called when a transaction certificate is being committed. Any speculative
    /// result whose read set overlaps with the certificate's write set must be
    /// invalidated to ensure correctness.
    pub fn invalidate_speculative_on_commit(&mut self, certificate: &TransactionCertificate) {
        // Collect all nodes being written by this certificate
        let written_nodes: HashSet<NodeId> = certificate
            .shard_proofs
            .values()
            .flat_map(|cert| cert.state_writes.iter().map(|w| w.node_id))
            .collect();

        if written_nodes.is_empty() {
            return;
        }

        // Find speculative txs that read from any written node
        let mut to_invalidate = HashSet::new();
        for node_id in &written_nodes {
            if let Some(tx_hashes) = self.speculative_reads_index.get(node_id) {
                to_invalidate.extend(tx_hashes.iter().cloned());
            }
        }

        // Remove invalidated results
        for tx_hash in to_invalidate {
            self.remove_speculative_result(&tx_hash);
            self.speculative_invalidated_count += 1;
            tracing::debug!(
                tx_hash = ?tx_hash,
                "Invalidated speculative execution due to state conflict"
            );
        }
    }

    /// Remove a speculative result and clean up its index entries.
    fn remove_speculative_result(&mut self, tx_hash: &Hash) {
        if let Some(spec) = self.speculative_results.remove(tx_hash) {
            // Clean up reads index
            for node_id in &spec.read_set {
                if let Some(set) = self.speculative_reads_index.get_mut(node_id) {
                    set.remove(tx_hash);
                    if set.is_empty() {
                        self.speculative_reads_index.remove(node_id);
                    }
                }
            }
        }
    }

    /// Try to use a cached speculative result for a transaction.
    ///
    /// Returns Some(result) if a valid cached result exists, None otherwise.
    /// Removes the result from the cache if found.
    ///
    /// Note: Call `record_speculative_cache_miss()` separately when falling back
    /// to normal execution for a transaction that was speculatively executed.
    pub fn take_speculative_result(&mut self, tx_hash: &Hash) -> Option<ExecutionResult> {
        if let Some(spec) = self.speculative_results.remove(tx_hash) {
            // Clean up reads index
            for node_id in &spec.read_set {
                if let Some(set) = self.speculative_reads_index.get_mut(node_id) {
                    set.remove(tx_hash);
                    if set.is_empty() {
                        self.speculative_reads_index.remove(node_id);
                    }
                }
            }

            self.speculative_cache_hit_count += 1;

            tracing::debug!(
                tx_hash = ?tx_hash,
                "Using cached speculative execution result"
            );

            Some(spec.result)
        } else {
            None
        }
    }

    /// Record a cache miss (called when falling back to normal execution).
    pub fn record_speculative_cache_miss(&mut self) {
        self.speculative_cache_miss_count += 1;
    }

    /// Record a late hit (speculation completed after commit but we waited for it).
    /// This counts as both a hit and a late hit.
    fn record_speculative_late_hit(&mut self) {
        self.speculative_cache_hit_count += 1;
        self.speculative_late_hit_count += 1;
    }

    /// Check if a speculative result exists for a transaction.
    pub fn has_speculative_result(&self, tx_hash: &Hash) -> bool {
        self.speculative_results.contains_key(tx_hash)
    }

    /// Check if speculative execution is in flight for a transaction.
    pub fn is_speculative_in_flight_for_tx(&self, tx_hash: &Hash) -> bool {
        self.speculative_in_flight_txs.contains(tx_hash)
    }

    /// Cleanup stale speculative results that have exceeded the max age.
    ///
    /// Called periodically (e.g., on CleanupTimer) to prevent memory growth
    /// from speculative results that were never used.
    pub fn cleanup_stale_speculative(&mut self, max_age: Duration) {
        let now = self.now;
        let stale: Vec<Hash> = self
            .speculative_results
            .iter()
            .filter(|(_, spec)| now.saturating_sub(spec.created_at) > max_age)
            .map(|(hash, _)| *hash)
            .collect();

        for tx_hash in stale {
            self.remove_speculative_result(&tx_hash);
            tracing::debug!(
                tx_hash = ?tx_hash,
                "Removed stale speculative result"
            );
        }
    }

    /// Get the number of cached speculative results.
    pub fn speculative_cache_size(&self) -> usize {
        self.speculative_results.len()
    }

    /// Get the number of transactions with speculative execution in flight.
    pub fn speculative_in_flight_count(&self) -> usize {
        self.speculative_in_flight_txs.len()
    }

    /// Get and reset speculative execution metrics.
    ///
    /// Returns (started, cache_hits, late_hits, cache_misses, invalidated) and resets counters to 0.
    /// Note: late_hits is a subset of cache_hits (both are incremented for late hits).
    pub fn take_speculative_metrics(&mut self) -> (u64, u64, u64, u64, u64) {
        let metrics = (
            self.speculative_started_count,
            self.speculative_cache_hit_count,
            self.speculative_late_hit_count,
            self.speculative_cache_miss_count,
            self.speculative_invalidated_count,
        );
        self.speculative_started_count = 0;
        self.speculative_cache_hit_count = 0;
        self.speculative_late_hit_count = 0;
        self.speculative_cache_miss_count = 0;
        self.speculative_invalidated_count = 0;
        metrics
    }

    /// Get the number of cross-shard transactions currently in flight.
    ///
    /// Counts unique transaction hashes across all cross-shard tracking phases:
    /// - Provisioning phase (waiting for state provisions from other shards)
    /// - Vote aggregation phase (waiting for vote quorum)
    /// - Certificate collection phase (waiting for certificates from all shards)
    ///
    /// Note: Actual provision tracking is handled by ProvisionCoordinator.
    /// This counts transactions in pending_provisioning and certificate_trackers.
    pub fn cross_shard_pending_count(&self) -> usize {
        // Use a HashSet to count unique transactions since a tx might be in multiple phases
        let mut pending_txs = HashSet::new();

        // Phase 1-2: Waiting for provisioning (tracked by ProvisionCoordinator)
        pending_txs.extend(self.pending_provisioning.keys());

        // Phase 3-5: Vote aggregation and certificate collection
        // Cross-shard txs will have certificate_trackers with multiple shards.
        for (tx_hash, tracker) in &self.certificate_trackers {
            if tracker.expected_count() > 1 {
                pending_txs.insert(*tx_hash);
            }
        }

        pending_txs.len()
    }
}

impl std::fmt::Debug for ExecutionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionState")
            .field("validator_id", &self.validator_id())
            .field("shard", &self.local_shard())
            .field("executed_txs", &self.executed_txs.len())
            .field("finalized_certificates", &self.finalized_certificates.len())
            .field("pending_provisioning", &self.pending_provisioning.len())
            .field("vote_trackers", &self.vote_trackers.len())
            .field("certificate_trackers", &self.certificate_trackers.len())
            .finish()
    }
}

impl SubStateMachine for ExecutionState {
    fn try_handle(&mut self, event: &Event) -> Option<Vec<Action>> {
        match event {
            Event::BlockCommitted {
                block_hash,
                height,
                block,
            } => {
                // Now we have the full block with transactions from all sections
                let all_txs: Vec<_> = block.all_transactions().cloned().collect();
                Some(self.on_block_committed(*block_hash, *height, all_txs))
            }
            // TransactionsExecuted and CrossShardTransactionsExecuted are no longer used.
            // Runners now sign votes directly and send StateVoteReceived events.
            Event::TransactionsExecuted { .. } | Event::CrossShardTransactionsExecuted { .. } => {
                Some(vec![])
            }
            Event::ProvisioningComplete {
                tx_hash,
                provisions,
            } => Some(self.on_provisioning_complete(*tx_hash, provisions.clone())),
            Event::StateVoteReceived { vote } => Some(self.on_vote(vote.clone())),
            Event::StateCertificateReceived { cert } => Some(self.on_certificate(cert.clone())),
            Event::StateEntriesFetched { tx_hash, entries } => {
                Some(self.on_state_entries_fetched(*tx_hash, entries.clone()))
            }
            // Signature verification callbacks
            Event::StateVotesVerifiedAndAggregated {
                tx_hash,
                verified_votes,
            } => Some(self.on_state_votes_verified(*tx_hash, verified_votes.clone())),
            Event::StateCertificateSignatureVerified { certificate, valid } => {
                Some(self.on_certificate_verified(certificate.clone(), *valid))
            }
            // Speculative execution callback
            Event::SpeculativeExecutionComplete {
                block_hash,
                results,
            } => Some(self.on_speculative_execution_complete(*block_hash, results.clone())),
            // BLS aggregation callback
            Event::StateCertificateAggregated {
                tx_hash,
                certificate,
            } => Some(self.on_state_certificate_aggregated(*tx_hash, certificate.clone())),
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
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{StaticTopology, ValidatorInfo, ValidatorSet};

    fn make_test_topology() -> Arc<dyn Topology> {
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

        Arc::new(StaticTopology::new(ValidatorId(0), 1, validator_set))
    }

    fn make_test_state() -> ExecutionState {
        let topology = make_test_topology();
        let signing_key = KeyPair::generate_bls();
        ExecutionState::new(topology, signing_key)
    }

    #[test]
    fn test_execution_state_creation() {
        let state = make_test_state();
        assert!(state.finalized_certificates.is_empty());
    }

    #[test]
    fn test_single_shard_execution_flow() {
        let mut state = make_test_state();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let block_hash = Hash::from_bytes(b"block1");

        // Block committed with transaction
        let actions = state.on_block_committed(block_hash, 1, vec![Arc::new(tx.clone())]);

        // Should request execution (single-shard path) - now also sets up vote tracking
        assert!(!actions.is_empty());
        // First action should be ExecuteTransactions
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // Transaction should be marked as executed
        assert!(state.is_executed(&tx_hash));

        // Vote tracker should be set up
        assert!(state.is_tracking_votes(&tx_hash));

        // In production, the runner executes + signs + sends StateVoteReceived.
        // Simulate that by creating a vote and calling on_vote.
        let state_root = Hash::ZERO;
        let success = true;
        let local_shard = state.local_shard();
        let validator_id = state.validator_id();

        // Create a signed vote (simulating what the runner does)
        let message =
            hyperscale_types::exec_vote_message(&tx_hash, &state_root, local_shard, success);
        let signature = state.signing_key.sign(&message);

        let vote = StateVoteBlock {
            transaction_hash: tx_hash,
            shard_group_id: local_shard,
            state_root,
            success,
            validator: validator_id,
            signature,
        };

        // Simulate runner sending StateVoteReceived for our own vote
        let actions = state.on_vote(vote);

        // Should not emit any broadcast action (runner handles broadcast)
        // Our vote is handled internally - might trigger certificate aggregation if quorum reached

        // With 4 validators and quorum threshold (2*4+1)/3 = 3,
        // single validator vote won't reach quorum yet
        // In a real test, we'd simulate receiving votes from other validators

        // For now, just verify the vote was counted
        let _ = actions; // Actions depend on quorum configuration
    }

    #[test]
    fn test_deduplication() {
        let mut state = make_test_state();

        let tx = test_transaction(1);
        let block_hash = Hash::from_bytes(b"block1");

        // First commit - should produce status change + execute transaction actions
        let actions1 = state.on_block_committed(block_hash, 1, vec![Arc::new(tx.clone())]);
        assert!(!actions1.is_empty()); // Status change + execute

        // Second commit of same transaction
        let block_hash2 = Hash::from_bytes(b"block2");
        let actions2 = state.on_block_committed(block_hash2, 2, vec![Arc::new(tx)]);

        // Should be empty (deduplicated)
        assert!(actions2.is_empty());
    }

    // Note: Tracker-specific tests have been moved to their respective modules:
    // - trackers/provisioning.rs
    // - trackers/vote.rs
    // - trackers/certificate.rs

    #[test]
    fn test_speculative_hit_before_commit() {
        // Scenario: Speculation completes BEFORE block commits (normal HIT)
        let mut state = make_test_state();

        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();
        let block_hash = Hash::from_bytes(b"block1");

        // Use height past view change cooldown (default cooldown is 3 rounds)
        let height = 10;

        // Trigger speculative execution
        let actions = state.trigger_speculative_execution(block_hash, height, vec![tx.clone()]);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SpeculativeExecute { .. })));
        assert!(state.speculative_in_flight_txs.contains(&tx_hash));

        // Speculation completes
        let spec_results = vec![(
            tx_hash,
            ExecutionResult {
                transaction_hash: tx_hash,
                success: true,
                state_root: Hash::ZERO,
                writes: vec![],
                error: None,
            },
        )];
        let _ = state.on_speculative_execution_complete(block_hash, spec_results);

        // Result should be cached
        assert!(state.has_speculative_result(&tx_hash));
        assert!(!state.speculative_in_flight_txs.contains(&tx_hash));

        // Now block commits - should use cached result (HIT)
        let actions = state.on_block_committed(block_hash, height, vec![tx]);

        // Should NOT emit ExecuteTransactions (speculation was used)
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // Should emit SignExecutionResults for the runner to sign and broadcast
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SignExecutionResults { .. })));
    }

    #[test]
    fn test_speculative_late_hit_commit_before_complete() {
        // Scenario: Block commits BEFORE speculation completes (LATE HIT)
        let mut state = make_test_state();

        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();
        let block_hash = Hash::from_bytes(b"block1");

        // Use height past view change cooldown (default cooldown is 3 rounds)
        let height = 10;

        // Trigger speculative execution
        let actions = state.trigger_speculative_execution(block_hash, height, vec![tx.clone()]);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SpeculativeExecute { .. })));
        assert!(state.speculative_in_flight_txs.contains(&tx_hash));

        // Block commits BEFORE speculation completes
        let commit_actions = state.on_block_committed(block_hash, height, vec![tx]);

        // Should NOT emit ExecuteTransactions (waiting for speculation)
        assert!(!commit_actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // Should be tracked as awaiting speculation
        assert!(state.committed_awaiting_speculation.contains_key(&tx_hash));
        // Still in-flight
        assert!(state.speculative_in_flight_txs.contains(&tx_hash));

        // Now speculation completes
        let spec_results = vec![(
            tx_hash,
            ExecutionResult {
                transaction_hash: tx_hash,
                success: true,
                state_root: Hash::ZERO,
                writes: vec![],
                error: None,
            },
        )];
        let complete_actions = state.on_speculative_execution_complete(block_hash, spec_results);

        // Should process the result immediately (late hit)
        // Should emit SignExecutionResults for the runner to sign and broadcast
        assert!(complete_actions
            .iter()
            .any(|a| matches!(a, Action::SignExecutionResults { .. })));

        // Should no longer be awaiting
        assert!(!state.committed_awaiting_speculation.contains_key(&tx_hash));
        assert!(!state.speculative_in_flight_txs.contains(&tx_hash));
    }

    #[test]
    fn test_speculative_miss_no_speculation() {
        // Scenario: No speculation was triggered (MISS - normal execution)
        let mut state = make_test_state();

        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();
        let block_hash = Hash::from_bytes(b"block1");

        // Block commits without any speculation
        let actions = state.on_block_committed(block_hash, 1, vec![tx]);

        // Should emit ExecuteTransactions (no speculation to use)
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // Should not be awaiting speculation
        assert!(!state.committed_awaiting_speculation.contains_key(&tx_hash));
    }
}
