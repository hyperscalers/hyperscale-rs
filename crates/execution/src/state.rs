//! Execution state machine.
//!
//! Handles transaction execution after blocks are committed.
//!
//! # Transaction Types
//!
//! - **Single-shard**: Execute locally, then vote within shard for BLS signature aggregation.
//! - **Cross-shard**: Atomic execution protocol with provisioning, voting, and finalization.
//!
//! # Cross-Shard Atomic Execution Protocol
//!
//! ## Phase 1: State Provisioning
//! When a block commits with cross-shard transactions, the block proposer broadcasts
//! state provisions (with merkle inclusion proofs) to target shards.
//!
//! ## Phase 2: Provision Verification
//! Target shards receive provisions, verify the QC signature and merkle proofs
//! against the committed state root, then mark provisioning complete.
//!
//! ## Phase 3: Deterministic Execution
//! With provisioned state, validators execute the transaction and create
//! an ExecutionVote with the receipt hash of execution results.
//!
//! ## Phase 4: Vote Aggregation
//! Validators broadcast votes to their local shard. When 2f+1 voting power agrees
//! on the same receipt hash, an ExecutionCertificate is created and broadcast to
//! remote participating shards (local peers form it independently).
//!
//! ## Phase 5: Finalization
//! Validators collect ExecutionCertificates from all participating shards. When all
//! certificates are received, a TransactionCertificate is created.

use hyperscale_core::{Action, ProtocolEvent, ProvisionRequest};
use hyperscale_types::{
    BlockHeight, Bls12381G1PublicKey, ExecutionCertificate, ExecutionWaveVote, Hash, NodeId,
    RoutableTransaction, ShardGroupId, StateProvision, TopologySnapshot, TransactionCertificate,
    TransactionDecision, ValidatorId, WaveId,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

use crate::execution_cache::ExecutionCache;
use crate::pending::{PendingCertificateVerification, PendingFetchedCertificateVerification};
use crate::trackers::{CertificateTracker, WaveVoteTracker};
use crate::wave_accumulator::WaveAccumulator;

/// Number of blocks to retain executed transaction hashes for deduplication.
/// This prevents re-execution of recently committed transactions while allowing
/// cleanup of old entries to prevent unbounded memory growth.
const EXECUTED_TX_RETENTION_BLOCKS: u64 = 50;

/// Number of blocks to retain early arrival votes/certificates before cleanup.
/// If an early arrival hasn't been processed within this many blocks, it's
/// likely stale and should be removed to prevent unbounded memory growth.
const EARLY_ARRIVAL_RETENTION_BLOCKS: u64 = 500;

/// Data returned when a wave completes (all txs executed).
///
/// The state machine produces this; the io_loop uses it to sign the wave vote
/// and broadcast (since the state machine doesn't hold the signing key).
#[derive(Debug)]
pub struct WaveCompletionData {
    /// Block this wave belongs to.
    pub block_hash: Hash,
    /// Block height.
    pub block_height: u64,
    /// Wave identifier.
    pub wave_id: WaveId,
    /// Merkle root over per-tx outcome leaves.
    pub wave_receipt_root: Hash,
    /// Per-tx outcomes in wave order.
    pub tx_outcomes: Vec<hyperscale_types::WaveTxOutcome>,
    /// All participating shards (union across all txs in wave).
    pub participating_shards: Vec<ShardGroupId>,
}

/// Key type for the pending verifications reverse index.
/// Identifies which type of verification and the secondary key (validator or shard).
/// Note: Provision verification is handled by ProvisionCoordinator.
/// Note: Vote verification is handled by VoteTracker with deferred batch verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingVerificationKey {
    /// Pending certificate verification for a shard.
    Certificate(ShardGroupId),
}

/// Cached entry for speculative execution.
///
/// With inline signing, the votes have already been signed and sent when
/// speculative execution completes. This entry just tracks that the tx was
/// speculatively executed so we can skip re-execution when the block commits.
///
/// The read_set is kept for invalidation: if a conflicting write commits before
/// this block, the speculative execution is invalidated and the transaction will
/// be re-executed normally when the block commits.
#[derive(Debug, Clone)]
pub struct SpeculativeResult {
    /// NodeIds that were READ during execution (for invalidation).
    /// Populated from the transaction's declared_reads.
    pub read_set: HashSet<NodeId>,
    /// When this speculative execution completed.
    pub created_at: Duration,
}

/// Execution state machine.
///
/// Handles transaction execution after blocks are committed.
pub struct ExecutionState {
    /// Current time.
    now: Duration,

    /// In-memory cache of execution write sets (DatabaseUpdates), keyed by tx hash.
    /// Populated when execution completes, read during block commit, evicted after commit.
    execution_cache: ExecutionCache,

    /// Transactions that have been executed (deduplication).
    /// Maps tx_hash -> block_height when executed, enabling height-based cleanup.
    executed_txs: HashMap<Hash, u64>,

    /// Finalized transaction certificates ready for block inclusion.
    /// Uses BTreeMap for deterministic iteration order.
    finalized_certificates: BTreeMap<Hash, Arc<TransactionCertificate>>,

    /// Current committed height for pruning stale entries.
    committed_height: u64,

    // ═══════════════════════════════════════════════════════════════════════
    // Cross-shard state (Phase 1-2: Provisioning)
    // ═══════════════════════════════════════════════════════════════════════
    /// Transactions waiting for provisioning to complete before execution.
    /// Maps tx_hash -> (transaction, block_height)
    /// Note: Provision tracking is handled by ProvisionCoordinator.
    pending_provisioning: HashMap<Hash, (Arc<RoutableTransaction>, u64)>,

    // ═══════════════════════════════════════════════════════════════════════
    // Wave-based voting state
    // ═══════════════════════════════════════════════════════════════════════
    /// Wave accumulators: collect per-tx execution results within each wave.
    /// Keyed by (block_hash, wave_id) to handle multiple blocks in flight.
    wave_accumulators: HashMap<(Hash, WaveId), WaveAccumulator>,

    /// Wave vote trackers: collect wave votes from other validators.
    /// Keyed by (block_hash, wave_id).
    wave_vote_trackers: HashMap<(Hash, WaveId), WaveVoteTracker>,

    /// Tx → wave assignment lookup for the current block.
    /// Maps tx_hash → (block_hash, wave_id).
    wave_assignments: HashMap<Hash, (Hash, WaveId)>,

    /// Early wave votes that arrived before tracking started.
    /// Keyed by (block_hash, wave_id).
    early_wave_votes: HashMap<(Hash, WaveId), Vec<ExecutionWaveVote>>,

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

    /// Certificates that arrived before tracking started.
    /// Tracks (certificates, first_arrival_height) for cleanup of stale entries.
    early_certificates: HashMap<Hash, (Vec<ExecutionCertificate>, u64)>,

    // ═══════════════════════════════════════════════════════════════════════
    // Pending signature verifications
    // ═══════════════════════════════════════════════════════════════════════
    /// Note: Provision verification (QC + merkle proofs) is delegated via VerifyStateProvisions action.
    /// Note: Vote signature verification is handled by VoteTracker with deferred batch verification.

    /// Certificates awaiting signature verification.
    /// Maps (tx_hash, shard_id) -> PendingCertificateVerification
    pending_cert_verifications: HashMap<(Hash, ShardGroupId), PendingCertificateVerification>,

    /// Fetched TransactionCertificates awaiting verification of all embedded ExecutionCertificates.
    /// Maps tx_hash -> PendingFetchedCertificateVerification
    pending_fetched_cert_verifications: HashMap<Hash, PendingFetchedCertificateVerification>,

    /// Reverse index: tx_hash -> set of pending verification keys.
    /// Enables O(k) cleanup instead of O(n) where k = verifications for this tx, n = total.
    pending_verifications_by_tx: HashMap<Hash, HashSet<PendingVerificationKey>>,

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

impl Default for ExecutionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Default maximum transactions for speculative execution (in-flight + cached).
pub const DEFAULT_SPECULATIVE_MAX_TXS: usize = 500;

/// Default number of rounds to pause speculation after a view change.
pub const DEFAULT_VIEW_CHANGE_COOLDOWN_ROUNDS: u64 = 3;

impl ExecutionState {
    /// Create a new execution state machine with default settings.
    pub fn new() -> Self {
        Self::with_speculative_config(
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
        speculative_max_txs: usize,
        view_change_cooldown_rounds: u64,
    ) -> Self {
        Self {
            now: Duration::ZERO,
            execution_cache: ExecutionCache::new(),
            executed_txs: HashMap::new(),
            finalized_certificates: BTreeMap::new(),
            committed_height: 0,
            pending_provisioning: HashMap::new(),
            wave_accumulators: HashMap::new(),
            wave_vote_trackers: HashMap::new(),
            wave_assignments: HashMap::new(),
            early_wave_votes: HashMap::new(),
            certificate_trackers: HashMap::new(),
            early_provisioning_complete: HashMap::new(),
            early_certificates: HashMap::new(),
            pending_cert_verifications: HashMap::new(),
            pending_fetched_cert_verifications: HashMap::new(),
            pending_verifications_by_tx: HashMap::new(),
            speculative_results: HashMap::new(),
            speculative_in_flight_txs: HashSet::new(),
            speculative_reads_index: HashMap::new(),
            pending_speculative_executions: HashMap::new(),
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
    // Time Management
    // ═══════════════════════════════════════════════════════════════════════════

    /// Set the current time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Execution Cache
    // ═══════════════════════════════════════════════════════════════════════════

    /// Read access to the execution cache (for block commit / state root verification).
    pub fn execution_cache(&self) -> &ExecutionCache {
        &self.execution_cache
    }

    /// Mutable access to the execution cache (for inserting results / evicting after commit).
    pub fn execution_cache_mut(&mut self) -> &mut ExecutionCache {
        &mut self.execution_cache
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Wave Assignment
    // ═══════════════════════════════════════════════════════════════════════════

    /// Compute deterministic wave assignments for a block's transactions.
    ///
    /// Partitions transactions by their provision dependency set (remote shards
    /// needed). All validators compute identical assignments from the same block.
    ///
    /// Returns a map from WaveId to list of (tx_hash, participating_shards) in
    /// block order within each wave.
    fn assign_waves(
        &self,
        topology: &TopologySnapshot,
        transactions: &[Arc<RoutableTransaction>],
    ) -> BTreeMap<WaveId, Vec<(Hash, Vec<ShardGroupId>)>> {
        let local_shard = topology.local_shard();
        let mut waves: BTreeMap<WaveId, Vec<(Hash, Vec<ShardGroupId>)>> = BTreeMap::new();

        for tx in transactions {
            let tx_hash = tx.hash();

            // Compute provision dependency set = remote shards needed
            let all_shards: BTreeSet<ShardGroupId> = topology
                .all_shards_for_transaction(tx)
                .into_iter()
                .collect();

            let remote_shards: BTreeSet<ShardGroupId> = all_shards
                .iter()
                .filter(|&&s| s != local_shard)
                .copied()
                .collect();

            let wave_id = WaveId(remote_shards);
            let participating: Vec<ShardGroupId> = all_shards.into_iter().collect();

            waves
                .entry(wave_id)
                .or_default()
                .push((tx_hash, participating));
        }

        waves
    }

    /// Set up wave accumulators and vote trackers for a newly committed block.
    ///
    /// Creates a `WaveAccumulator` and `WaveVoteTracker` per wave, and records
    /// the tx → wave mapping for later result routing.
    ///
    /// Returns any early wave votes that arrived before tracking was set up,
    /// so the caller can replay them through `on_wave_vote()`.
    fn setup_wave_tracking(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: Hash,
        block_height: u64,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Vec<ExecutionWaveVote> {
        let waves = self.assign_waves(topology, transactions);
        let quorum = topology.local_quorum_threshold();
        let mut votes_to_replay = Vec::new();

        for (wave_id, txs) in waves {
            let key = (block_hash, wave_id.clone());

            // Record tx → wave assignments
            for (tx_hash, _) in &txs {
                self.wave_assignments
                    .insert(*tx_hash, (block_hash, wave_id.clone()));
            }

            // Create accumulator
            let accumulator = WaveAccumulator::new(wave_id.clone(), block_hash, block_height, txs);
            self.wave_accumulators.insert(key.clone(), accumulator);

            // Create vote tracker
            let tracker = WaveVoteTracker::new(wave_id, block_hash, quorum);
            self.wave_vote_trackers.insert(key.clone(), tracker);

            // Collect early wave votes for caller to replay through on_wave_vote()
            if let Some(early_votes) = self.early_wave_votes.remove(&key) {
                tracing::debug!(
                    block_hash = ?block_hash,
                    wave = ?key.1,
                    count = early_votes.len(),
                    "Collected early wave votes for replay"
                );
                votes_to_replay.extend(early_votes);
            }
        }

        tracing::debug!(
            block_hash = ?block_hash,
            wave_count = self.wave_accumulators.iter()
                .filter(|((bh, _), _)| *bh == block_hash)
                .count(),
            "Wave tracking set up for block"
        );

        votes_to_replay
    }

    /// Record a transaction execution result into the appropriate wave accumulator.
    ///
    /// If the wave becomes complete (all txs executed), returns the wave data
    /// needed for signing. The caller (io_loop) handles signing since the state
    /// machine doesn't hold the signing key.
    ///
    /// Returns `Some((wave_key, receipt_root, tx_outcomes))` if wave is complete.
    pub fn record_wave_result(
        &mut self,
        tx_hash: Hash,
        receipt_hash: Hash,
        success: bool,
        write_nodes: Vec<NodeId>,
    ) -> Option<WaveCompletionData> {
        let wave_key = self.wave_assignments.get(&tx_hash)?.clone();

        let accumulator = self.wave_accumulators.get_mut(&wave_key)?;

        if !accumulator.record_result(tx_hash, receipt_hash, success, write_nodes) {
            return None;
        }

        // Wave complete — build receipt tree
        let (wave_receipt_root, tx_outcomes) = accumulator
            .build_wave_data()
            .expect("wave is complete but build_wave_data returned None");

        let block_hash = accumulator.block_hash();
        let block_height = accumulator.block_height();
        let wave_id = accumulator.wave_id().clone();
        let participating_shards = accumulator.all_participating_shards();

        tracing::debug!(
            ?block_hash,
            wave = %wave_id,
            tx_count = tx_outcomes.len(),
            "Wave complete — ready for vote signing"
        );

        Some(WaveCompletionData {
            block_hash,
            block_height,
            wave_id,
            wave_receipt_root,
            tx_outcomes,
            participating_shards,
        })
    }

    /// Record a transaction deferral into the appropriate wave accumulator.
    ///
    /// Deferrals are terminal — the tx won't execute on this block. The wave
    /// accumulator records it with a zeroed receipt_hash and success=false.
    /// If this was the last unresolved tx in the wave, returns completion data
    /// for wave vote signing.
    pub fn record_wave_deferral(&mut self, tx_hash: Hash) -> Option<WaveCompletionData> {
        self.record_wave_result(tx_hash, Hash::ZERO, false, vec![])
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Wave Vote Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle an execution wave vote received from another validator (or self).
    ///
    /// Routes to the appropriate `WaveVoteTracker` for deferred verification.
    pub fn on_wave_vote(
        &mut self,
        topology: &TopologySnapshot,
        vote: ExecutionWaveVote,
    ) -> Vec<Action> {
        let key = (vote.block_hash, vote.wave_id.clone());
        let validator_id = vote.validator;

        // Check if we're tracking this wave
        if !self.wave_vote_trackers.contains_key(&key) {
            // Buffer for later
            self.early_wave_votes.entry(key).or_default().push(vote);
            return vec![];
        }

        // Skip verification for our own vote
        if validator_id == topology.local_validator_id() {
            return self.handle_verified_wave_vote(topology, vote);
        }

        // Get public key for signature verification
        let Some(public_key) = topology.public_key(validator_id) else {
            tracing::warn!(
                validator = validator_id.0,
                "Unknown validator for wave vote"
            );
            return vec![];
        };

        let voting_power = topology.voting_power(validator_id).unwrap_or(0);

        let tracker = self.wave_vote_trackers.get_mut(&key).unwrap();

        if tracker.has_seen_validator(validator_id) {
            return vec![];
        }

        tracker.buffer_unverified_vote(vote, public_key, voting_power);

        self.maybe_trigger_wave_vote_verification(key)
    }

    /// Check if we should trigger batch verification for a wave's votes.
    fn maybe_trigger_wave_vote_verification(&mut self, key: (Hash, WaveId)) -> Vec<Action> {
        let Some(tracker) = self.wave_vote_trackers.get_mut(&key) else {
            return vec![];
        };

        if !tracker.should_trigger_verification() {
            return vec![];
        }

        let votes = tracker.take_unverified_votes();
        if votes.is_empty() {
            return vec![];
        }

        vec![Action::VerifyAndAggregateExecutionWaveVotes {
            wave_id: key.1,
            block_hash: key.0,
            votes,
        }]
    }

    /// Handle a verified wave vote (own vote or already-verified).
    fn handle_verified_wave_vote(
        &mut self,
        topology: &TopologySnapshot,
        vote: ExecutionWaveVote,
    ) -> Vec<Action> {
        let key = (vote.block_hash, vote.wave_id.clone());
        let voting_power = topology.voting_power(vote.validator).unwrap_or(0);

        let Some(tracker) = self.wave_vote_trackers.get_mut(&key) else {
            return vec![];
        };

        tracker.add_verified_vote(vote, voting_power);

        self.check_wave_vote_quorum(topology, key)
    }

    /// Handle batch wave vote verification completed.
    pub fn on_wave_votes_verified(
        &mut self,
        topology: &TopologySnapshot,
        wave_id: WaveId,
        block_hash: Hash,
        verified_votes: Vec<(ExecutionWaveVote, u64)>,
    ) -> Vec<Action> {
        let key = (block_hash, wave_id);

        let Some(tracker) = self.wave_vote_trackers.get_mut(&key) else {
            return vec![];
        };

        tracker.on_verification_complete();

        for (vote, power) in verified_votes {
            tracker.add_verified_vote(vote, power);
        }

        let mut actions = self.check_wave_vote_quorum(topology, key.clone());
        actions.extend(self.maybe_trigger_wave_vote_verification(key));
        actions
    }

    /// Check if quorum is reached for a wave's votes.
    fn check_wave_vote_quorum(
        &mut self,
        topology: &TopologySnapshot,
        key: (Hash, WaveId),
    ) -> Vec<Action> {
        let Some(tracker) = self.wave_vote_trackers.get_mut(&key) else {
            return vec![];
        };

        let Some((wave_receipt_root, _total_power)) = tracker.check_quorum() else {
            return vec![];
        };

        let votes = tracker.take_votes_for_receipt_root(&wave_receipt_root);
        let committee = topology.local_committee().to_vec();

        // Get tx_outcomes from the wave accumulator
        let tx_outcomes = self
            .wave_accumulators
            .get(&key)
            .and_then(|acc| acc.build_wave_data())
            .map(|(_, outcomes)| outcomes)
            .unwrap_or_default();

        tracing::debug!(
            block_hash = ?key.0,
            wave = %key.1,
            votes = votes.len(),
            "Wave vote quorum reached — delegating BLS aggregation"
        );

        vec![Action::AggregateExecutionWaveCertificate {
            wave_id: key.1,
            block_hash: key.0,
            shard: topology.local_shard(),
            wave_receipt_root,
            votes,
            tx_outcomes,
            committee,
        }]
    }

    /// Handle execution wave certificate aggregation completed.
    ///
    /// Called when the crypto pool finishes BLS aggregation for a wave's votes.
    /// Broadcasts the wave cert to remote shards, then extracts per-tx outcomes
    /// and feeds them to per-tx CertificateTrackers for finalization.
    pub fn on_wave_certificate_aggregated(
        &mut self,
        topology: &TopologySnapshot,
        wave_id: WaveId,
        certificate: hyperscale_types::ExecutionWaveCertificate,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let local_shard = topology.local_shard();
        let local_vid = topology.local_validator_id();
        let block_hash = certificate.block_hash;

        // Determine remote participating shards from the wave accumulator
        let key = (block_hash, wave_id.clone());
        let remote_shards: Vec<ShardGroupId> = self
            .wave_accumulators
            .get(&key)
            .map(|acc| {
                acc.all_participating_shards()
                    .into_iter()
                    .filter(|&s| s != local_shard)
                    .collect()
            })
            .unwrap_or_default();

        let certificate = Arc::new(certificate);

        // Broadcast wave cert to each remote participating shard
        for target_shard in &remote_shards {
            let recipients: Vec<ValidatorId> = topology
                .committee_for_shard(*target_shard)
                .iter()
                .copied()
                .filter(|&v| v != local_vid)
                .collect();
            actions.push(Action::BroadcastExecutionWaveCertificate {
                shard: *target_shard,
                certificate: Arc::clone(&certificate),
                recipients,
            });
        }

        tracing::debug!(
            ?block_hash,
            wave = %wave_id,
            tx_count = certificate.tx_outcomes.len(),
            remote_shards = remote_shards.len(),
            "Wave cert aggregated — broadcast to remote shards, feeding per-tx finalization"
        );

        // Feed each tx's outcome to per-tx CertificateTracker for finalization.
        // Create a synthetic ExecutionCertificate per tx from the wave cert data.
        // This bridges the wave path into the existing per-tx finalization path.
        for outcome in &certificate.tx_outcomes {
            let synthetic_cert = ExecutionCertificate {
                transaction_hash: outcome.tx_hash,
                shard_group_id: certificate.shard_group_id,
                read_nodes: vec![], // Not tracked in wave certs (available from execution cache)
                write_nodes: outcome.write_nodes.clone(),
                receipt_hash: outcome.receipt_hash,
                success: outcome.success,
                aggregated_signature: certificate.aggregated_signature,
                signers: certificate.signers.clone(),
            };

            actions.extend(self.handle_certificate_internal(topology, Arc::new(synthetic_cert)));
        }

        actions
    }

    /// Handle an execution wave certificate received from a remote shard.
    ///
    /// Delegates BLS signature verification to the crypto pool before processing.
    pub fn on_wave_certificate(
        &mut self,
        topology: &TopologySnapshot,
        cert: hyperscale_types::ExecutionWaveCertificate,
    ) -> Vec<Action> {
        let shard = cert.shard_group_id;

        // Check if we're tracking any txs from this wave cert.
        // If none of the cert's txs have certificate trackers, we don't need it.
        let any_tracked = cert
            .tx_outcomes
            .iter()
            .any(|o| self.certificate_trackers.contains_key(&o.tx_hash));

        if !any_tracked {
            // Check if any are already finalized
            let any_finalized = cert
                .tx_outcomes
                .iter()
                .any(|o| self.finalized_certificates.contains_key(&o.tx_hash));
            if any_finalized {
                return vec![];
            }
            // Buffer — block may not have committed yet
            // We don't have a wave-level early buffer for remote certs, so
            // buffer per-tx as synthetic ExecutionCertificates for compatibility
            let current_height = self.committed_height;
            for outcome in &cert.tx_outcomes {
                self.early_certificates
                    .entry(outcome.tx_hash)
                    .or_insert_with(|| (Vec::new(), current_height))
                    .0
                    .push(ExecutionCertificate {
                        transaction_hash: outcome.tx_hash,
                        shard_group_id: shard,
                        read_nodes: vec![],
                        write_nodes: outcome.write_nodes.clone(),
                        receipt_hash: outcome.receipt_hash,
                        success: outcome.success,
                        aggregated_signature: cert.aggregated_signature,
                        signers: cert.signers.clone(),
                    });
            }
            return vec![];
        }

        // Get public keys for the source shard's committee
        let committee = topology.committee_for_shard(shard);
        let public_keys: Vec<Bls12381G1PublicKey> = committee
            .iter()
            .filter_map(|&vid| topology.public_key(vid))
            .collect();

        if public_keys.len() != committee.len() {
            tracing::warn!(
                shard = shard.0,
                "Could not resolve all public keys for wave cert verification"
            );
            return vec![];
        }

        // Delegate signature verification to crypto pool
        vec![Action::VerifyExecutionWaveCertificateSignature {
            certificate: cert,
            public_keys,
        }]
    }

    /// Handle execution wave certificate signature verification result.
    ///
    /// If valid, extract per-tx outcomes and feed to CertificateTrackers.
    pub fn on_wave_certificate_verified(
        &mut self,
        topology: &TopologySnapshot,
        certificate: hyperscale_types::ExecutionWaveCertificate,
        valid: bool,
    ) -> Vec<Action> {
        if !valid {
            tracing::warn!(
                shard = certificate.shard_group_id.0,
                block_hash = ?certificate.block_hash,
                wave = %certificate.wave_id,
                "Invalid wave certificate signature"
            );
            return vec![];
        }

        let mut actions = Vec::new();

        // Extract per-tx outcomes and feed to CertificateTrackers
        for outcome in &certificate.tx_outcomes {
            let synthetic_cert = ExecutionCertificate {
                transaction_hash: outcome.tx_hash,
                shard_group_id: certificate.shard_group_id,
                read_nodes: vec![],
                write_nodes: outcome.write_nodes.clone(),
                receipt_hash: outcome.receipt_hash,
                success: outcome.success,
                aggregated_signature: certificate.aggregated_signature,
                signers: certificate.signers.clone(),
            };

            actions.extend(self.handle_certificate_internal(topology, Arc::new(synthetic_cert)));
        }

        actions
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
    #[allow(clippy::too_many_arguments)]
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: Hash,
        height: u64,
        block_timestamp: u64,
        proposer: ValidatorId,
        transactions: Vec<Arc<RoutableTransaction>>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        // ── Provision broadcasting (proposer only) ─────────────────────
        //
        // This runs on the FULL transaction list, before dedup filtering.
        // Provisioning is a block-level proposer duty: the proposer must
        // broadcast state entries for all cross-shard transactions in the
        // committed block, regardless of local execution state. The dedup
        // filter below controls re-execution, not provisioning.
        let local_shard = topology.local_shard();
        let is_proposer = topology.local_validator_id() == proposer;

        if is_proposer {
            let mut provision_requests = Vec::new();
            for tx in &transactions {
                if topology.is_single_shard_transaction(tx) {
                    continue;
                }
                let mut owned_nodes: Vec<_> = tx
                    .declared_reads
                    .iter()
                    .chain(tx.declared_writes.iter())
                    .filter(|&node_id| topology.shard_for_node_id(node_id) == local_shard)
                    .copied()
                    .collect();
                owned_nodes.sort();
                owned_nodes.dedup();

                if !owned_nodes.is_empty() {
                    let target_shards: Vec<_> = topology
                        .all_shards_for_transaction(tx)
                        .into_iter()
                        .filter(|&s| s != local_shard)
                        .collect();

                    if !target_shards.is_empty() {
                        provision_requests.push(ProvisionRequest {
                            tx_hash: tx.hash(),
                            nodes: owned_nodes,
                            target_shards,
                        });
                    }
                }
            }

            if !provision_requests.is_empty() {
                let local_vid = topology.local_validator_id();
                let mut shard_recipients = HashMap::new();
                for req in &provision_requests {
                    for &target_shard in &req.target_shards {
                        shard_recipients.entry(target_shard).or_insert_with(|| {
                            topology
                                .committee_for_shard(target_shard)
                                .iter()
                                .copied()
                                .filter(|&v| v != local_vid)
                                .collect()
                        });
                    }
                }
                actions.push(Action::FetchAndBroadcastProvisions {
                    requests: provision_requests,
                    source_shard: local_shard,
                    block_height: BlockHeight(height),
                    block_timestamp,
                    shard_recipients,
                });
            }
        }

        // ── Execution (dedup-filtered) ─────────────────────────────────
        //
        // Filter out already-executed transactions so we don't re-execute
        // or re-vote for transactions seen in earlier blocks.
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

        // Set up wave tracking for this block's transactions.
        // Returns any early wave votes that arrived before tracking was ready.
        let early_wave_votes = self.setup_wave_tracking(topology, block_hash, height, &new_txs);
        for vote in early_wave_votes {
            actions.extend(self.on_wave_vote(topology, vote));
        }

        // Prune old entries to prevent unbounded growth
        self.prune_executed_txs();
        self.prune_early_arrivals();

        // Separate single-shard and cross-shard transactions
        let (single_shard, cross_shard): (Vec<_>, Vec<_>) = new_txs
            .into_iter()
            .partition(|tx| topology.is_single_shard_transaction(tx));

        // Handle single-shard transactions (voting, same as cross-shard)
        // All WRITE operations need BLS signature aggregation
        //
        // With inline signing, speculative execution has already signed and sent votes.
        // We just need to:
        // 1. Check if speculation completed (votes already sent) - skip execution
        // 2. Check if speculation is in-flight (votes will arrive soon) - skip execution
        // 3. Otherwise execute normally
        let mut txs_needing_execution = Vec::new();

        for tx in single_shard {
            let tx_hash = tx.hash();

            if self.take_speculative_result(&tx_hash).is_some() {
                // Speculation completed - results already cached
                self.speculative_in_flight_txs.remove(&tx_hash);
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    "SPECULATIVE HIT: Results already cached, skipping execution"
                );
                actions.extend(self.start_single_shard_execution(topology, tx.clone()));
            } else if self.speculative_in_flight_txs.contains(&tx_hash) {
                // Speculation in-flight - results will arrive when it completes
                // This counts as a hit since we're skipping re-execution
                self.speculative_cache_hit_count += 1;
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    "SPECULATIVE IN-FLIGHT: Results will arrive soon, skipping execution"
                );
                actions.extend(self.start_single_shard_execution(topology, tx.clone()));
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

        // Start execution tracking for transactions that need execution
        for tx in &txs_needing_execution {
            actions.extend(self.start_single_shard_execution(topology, tx.clone()));
        }

        // Batch execute transactions that didn't have cached results
        if !txs_needing_execution.is_empty() {
            actions.push(Action::ExecuteTransactions {
                block_hash,
                transactions: txs_needing_execution,
                state_root: Hash::from_bytes(&[0u8; 32]),
            });
        }

        // Handle cross-shard execution tracking (dedup-filtered — don't re-track)
        for tx in cross_shard {
            actions.extend(self.start_cross_shard_execution(topology, tx, height));
        }

        actions
    }

    /// Start single-shard execution tracking.
    ///
    /// Sets up certificate tracking for finalization. Voting is handled by
    /// the wave path — no per-tx vote tracking needed.
    fn start_single_shard_execution(
        &mut self,
        topology: &TopologySnapshot,
        tx: Arc<RoutableTransaction>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let tx_hash = tx.hash();
        let local_shard = topology.local_shard();

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            "Starting single-shard execution tracking"
        );

        // Start tracking certificates for finalization (single shard only)
        let participating_shards: BTreeSet<_> = [local_shard].into_iter().collect();
        let cert_tracker = CertificateTracker::new(tx_hash, participating_shards);
        self.certificate_trackers.insert(tx_hash, cert_tracker);

        // Replay any early certificates that arrived before tracking started.
        if let Some((early_certs, _arrival_height)) = self.early_certificates.remove(&tx_hash) {
            tracing::debug!(
                tx_hash = ?tx_hash,
                count = early_certs.len(),
                "Replaying early certificates for single-shard tx"
            );
            for cert in early_certs {
                actions.extend(self.handle_certificate_internal(topology, Arc::new(cert)));
            }
        }

        actions
    }

    /// Start cross-shard execution (Phase 1: State Provisioning).
    ///
    /// Provision broadcasting is handled at the block level via
    /// `FetchAndBroadcastProvisions` — this method only sets up tracking.
    fn start_cross_shard_execution(
        &mut self,
        topology: &TopologySnapshot,
        tx: Arc<RoutableTransaction>,
        height: u64,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let tx_hash = tx.hash();
        let local_shard = topology.local_shard();

        // Identify all participating shards
        let participating_shards: BTreeSet<ShardGroupId> = topology
            .all_shards_for_transaction(&tx)
            .into_iter()
            .collect();

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            participating = ?participating_shards,
            "Starting cross-shard execution"
        );

        // Start tracking provisioning
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
            // Emit registration event for ProvisionCoordinator
            // The coordinator will handle provision tracking centrally
            actions.push(Action::Continuation(
                ProtocolEvent::CrossShardTxRegistered {
                    tx_hash,
                    required_shards: remote_shards,
                    committed_height: BlockHeight(height),
                },
            ));

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
                actions.extend(self.on_provisioning_complete(topology, tx_hash, provisions));
            }
        }

        // Start tracking certificates for finalization
        let cert_tracker = CertificateTracker::new(tx_hash, participating_shards.clone());
        self.certificate_trackers.insert(tx_hash, cert_tracker);

        // Replay any early certificates that arrived before tracking started.
        if let Some((early_certs, _arrival_height)) = self.early_certificates.remove(&tx_hash) {
            tracing::debug!(tx_hash = ?tx_hash, count = early_certs.len(), "Replaying early certificates");
            for cert in early_certs {
                actions.extend(self.handle_certificate_internal(topology, Arc::new(cert)));
            }
        }

        actions
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
        topology: &TopologySnapshot,
        tx_hash: Hash,
        provisions: Vec<StateProvision>,
    ) -> Vec<Action> {
        let local_shard = topology.local_shard();

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
    // Phase 5: Finalization
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle execution certificate signature verification result.
    #[instrument(skip(self, certificate), fields(
        tx_hash = ?certificate.transaction_hash,
        shard = certificate.shard_group_id.0,
        valid = valid
    ))]
    pub fn on_certificate_verified(
        &mut self,
        topology: &TopologySnapshot,
        certificate: ExecutionCertificate,
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

        // Otherwise, it's a gossiped certificate for cross-shard execution flow
        self.pending_cert_verifications.remove(&(tx_hash, shard));
        // Update reverse index
        if let Some(keys) = self.pending_verifications_by_tx.get_mut(&tx_hash) {
            keys.remove(&PendingVerificationKey::Certificate(shard));
        }

        if !valid {
            tracing::warn!(
                tx_hash = ?tx_hash,
                shard = shard.0,
                "Invalid execution certificate signature"
            );
            return vec![];
        }

        self.handle_certificate_internal(topology, Arc::new(certificate))
    }

    /// Handle verification result for a fetched certificate's ExecutionCertificate.
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
                "Invalid fetched certificate - ExecutionCertificate signature verification failed"
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
        vec![Action::Continuation(
            ProtocolEvent::FetchedCertificateVerified {
                block_hash: pending.block_hash,
                certificate: pending.certificate,
            },
        )]
    }

    /// Verify a fetched TransactionCertificate by checking all embedded ExecutionCertificates.
    ///
    /// Each ExecutionCertificate is verified against its shard's committee public keys.
    /// When all verify successfully, a FetchedCertificateVerified event is emitted.
    pub fn verify_fetched_certificate(
        &mut self,
        topology: &TopologySnapshot,
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
            return vec![Action::Continuation(
                ProtocolEvent::FetchedCertificateVerified {
                    block_hash,
                    certificate,
                },
            )];
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

        // Emit verification action for each embedded ExecutionCertificate
        for (shard_id, execution_cert) in &certificate.shard_proofs {
            // Get public keys for this shard's committee
            let committee = topology.committee_for_shard(*shard_id);
            let public_keys: Vec<Bls12381G1PublicKey> = committee
                .iter()
                .filter_map(|&vid| topology.public_key(vid))
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

            actions.push(Action::VerifyExecutionCertificateSignature {
                certificate: execution_cert.clone(),
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
    fn handle_certificate_internal(
        &mut self,
        topology: &TopologySnapshot,
        cert: Arc<ExecutionCertificate>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let tx_hash = cert.transaction_hash;
        let cert_shard = cert.shard_group_id;

        let local_shard = topology.local_shard();
        let Some(tracker) = self.certificate_trackers.get_mut(&tx_hash) else {
            tracing::debug!(
                tx_hash = ?tx_hash,
                cert_shard = cert_shard.0,
                local_shard = local_shard.0,
                "No certificate tracker for tx, ignoring certificate"
            );
            return actions;
        };

        let complete = tracker.add_certificate(Arc::unwrap_or_clone(cert));

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
                actions.push(Action::Continuation(ProtocolEvent::TransactionExecuted {
                    tx_hash,
                    accepted,
                }));
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
    /// Returns certificates that have been finalized but not yet committed to a block.
    /// Once committed, certificates are persisted to storage and should be fetched from there.
    pub fn get_finalized_certificate(&self, tx_hash: &Hash) -> Option<Arc<TransactionCertificate>> {
        self.finalized_certificates.get(tx_hash).cloned()
    }

    /// Remove a finalized certificate (after it's been included in a block).
    ///
    /// Cleans up all transaction tracking state. The certificate itself is already
    /// persisted to storage by this point and can be fetched from there by peers.
    pub fn remove_finalized_certificate(&mut self, tx_hash: &Hash) {
        // Remove from finalized certificates
        self.finalized_certificates.remove(tx_hash);

        // Evict from execution cache — writes have been applied to JVT at this point.
        self.execution_cache.remove(tx_hash);

        // Clean up all transaction tracking state now that it's finalized.
        // This is the same cleanup done by cleanup_transaction() for aborts/deferrals,
        // but we need to do it here for successful completions too.
        self.pending_provisioning.remove(tx_hash);

        self.certificate_trackers.remove(tx_hash);
        self.early_provisioning_complete.remove(tx_hash);
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

        let before_certs = self.early_certificates.len();
        self.early_certificates
            .retain(|_, (_, arrival_height)| *arrival_height > cutoff);
        let pruned_certs = before_certs - self.early_certificates.len();

        if pruned_provisions > 0 || pruned_certs > 0 {
            tracing::debug!(
                pruned_provisions,
                pruned_certs,
                cutoff_height = cutoff,
                "Pruned stale early arrivals"
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

    /// Get debug info about certificate tracking state for a transaction.
    pub fn certificate_tracking_debug(&self, tx_hash: &Hash) -> String {
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
            "cert_tracker={} ({}), early_certs={}",
            has_cert_tracker, cert_tracker_info, early_cert_count
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

        // Evict from execution cache — transaction is being retried or abandoned.
        self.execution_cache.remove(tx_hash);

        // Phase 1-2: Provisioning cleanup
        // Note: Provision tracking is handled by ProvisionCoordinator
        self.pending_provisioning.remove(tx_hash);

        // Phase 3-4: Vote cleanup

        // Wave voting cleanup
        if let Some(wave_key) = self.wave_assignments.remove(tx_hash) {
            // Don't remove the wave accumulator/tracker — other txs in the wave may still be active.
            // The wave accumulator will be cleaned up when all its txs are cleaned up or the block is abandoned.
            // Just remove this tx's assignment.
            let _ = wave_key;
        }

        // Phase 5: Certificate cleanup
        self.certificate_trackers.remove(tx_hash);

        // Early arrivals cleanup
        self.early_provisioning_complete.remove(tx_hash);
        self.early_certificates.remove(tx_hash);

        // Pending verifications cleanup using reverse index for O(k) instead of O(n)
        // Note: Provision verification (QC + merkle proofs) is delegated via VerifyStateProvisions action
        if let Some(keys) = self.pending_verifications_by_tx.remove(tx_hash) {
            for key in keys {
                match key {
                    PendingVerificationKey::Certificate(shard) => {
                        self.pending_cert_verifications.remove(&(*tx_hash, shard));
                    }
                }
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
    /// certificate tracking, vote aggregation, our own ExecutionCertificate, and pending verifications.
    ///
    /// Note: This keeps `executed_txs` for deduplication.
    pub fn cancel_certificate_building(&mut self, tx_hash: &Hash) {
        let had_tracker = self.certificate_trackers.remove(tx_hash).is_some();
        let had_early = self.early_certificates.remove(tx_hash).is_some();

        // Clean up pending fetched certificate verifications for this tx
        self.pending_fetched_cert_verifications.remove(tx_hash);

        // Clean up pending verifications using reverse index
        let mut removed_cert_count = 0;
        if let Some(keys) = self.pending_verifications_by_tx.remove(tx_hash) {
            for key in keys {
                match key {
                    PendingVerificationKey::Certificate(shard) => {
                        self.pending_cert_verifications.remove(&(*tx_hash, shard));
                        removed_cert_count += 1;
                    }
                }
            }
        }

        if had_tracker || had_early || removed_cert_count > 0 {
            tracing::debug!(
                tx_hash = %tx_hash,
                had_cert_tracker = had_tracker,
                removed_cert_verifications = removed_cert_count,
                "Cancelled local certificate building - using external certificate"
            );
        }
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
        topology: &TopologySnapshot,
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
            .filter(|tx| topology.is_single_shard_transaction(tx))
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
    /// With inline signing, the votes have already been signed and sent by the runner.
    /// This callback just updates tracking state so we know to skip re-execution
    /// when the block commits.
    #[instrument(skip(self, tx_hashes), fields(block_hash = ?block_hash, tx_count = tx_hashes.len()))]
    pub fn on_speculative_execution_complete(
        &mut self,
        block_hash: Hash,
        tx_hashes: Vec<Hash>,
    ) -> Vec<Action> {
        tracing::info!(
            block_hash = ?block_hash,
            tx_count = tx_hashes.len(),
            "SPECULATIVE COMPLETE: Votes already sent, updating cache tracking"
        );

        // Get the transactions we were executing to retrieve their declared_reads
        let transactions = self
            .pending_speculative_executions
            .remove(&block_hash)
            .unwrap_or_default();

        // Build a map from tx_hash to transaction for quick lookup
        let tx_map: HashMap<Hash, &Arc<RoutableTransaction>> =
            transactions.iter().map(|tx| (tx.hash(), tx)).collect();

        // Mark each transaction as speculatively executed (votes already sent)
        for tx_hash in tx_hashes {
            // Remove from in-flight tracking
            self.speculative_in_flight_txs.remove(&tx_hash);

            // Skip if already executed through some other path
            if self.executed_txs.contains_key(&tx_hash) {
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    "Skipping speculative cache - tx already executed"
                );
                continue;
            }

            // Get the read set from the transaction's declared_reads
            let read_set: HashSet<NodeId> = tx_map
                .get(&tx_hash)
                .map(|tx| tx.declared_reads.iter().copied().collect())
                .unwrap_or_default();

            // Index for fast invalidation
            for node_id in &read_set {
                self.speculative_reads_index
                    .entry(*node_id)
                    .or_default()
                    .insert(tx_hash);
            }

            // Cache entry (no result needed - votes already sent)
            self.speculative_results.insert(
                tx_hash,
                SpeculativeResult {
                    read_set,
                    created_at: self.now,
                },
            );

            tracing::debug!(
                tx_hash = ?tx_hash,
                block_hash = ?block_hash,
                "Marked as speculatively executed"
            );
        }

        // No actions needed - votes were already sent by the runner
        Vec::new()
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
            .flat_map(|cert| cert.write_nodes.iter().copied())
            .collect();

        if written_nodes.is_empty() {
            return;
        }

        // Single-pass: collect tx_hashes to invalidate by iterating written nodes,
        // then remove each speculative result. We avoid cloning by collecting
        // into a Vec directly (HashSet dedup happens via speculative_results.remove).
        //
        // Note: We can't inline the removal because remove_speculative_result
        // mutates speculative_reads_index, which we're reading from.
        let to_invalidate: Vec<Hash> = written_nodes
            .iter()
            .filter_map(|node_id| self.speculative_reads_index.get(node_id))
            .flatten()
            .copied()
            .collect();

        // Remove invalidated results (speculative_results.remove handles dedup)
        for tx_hash in to_invalidate {
            // Only count and log if we actually removed something (handles duplicates)
            if self.speculative_results.contains_key(&tx_hash) {
                self.remove_speculative_result(&tx_hash);
                self.speculative_invalidated_count += 1;
                tracing::debug!(
                    tx_hash = ?tx_hash,
                    "Invalidated speculative execution due to state conflict"
                );
            }
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
    ///
    /// With inline signing, this just returns true if the tx was speculatively
    /// executed (votes already sent). The caller should skip execution.
    pub fn take_speculative_result(&mut self, tx_hash: &Hash) -> Option<()> {
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
                "Speculative hit - votes already sent"
            );

            Some(())
        } else {
            None
        }
    }

    /// Record a cache miss (called when falling back to normal execution).
    pub fn record_speculative_cache_miss(&mut self) {
        self.speculative_cache_miss_count += 1;
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
            .field("executed_txs", &self.executed_txs.len())
            .field("finalized_certificates", &self.finalized_certificates.len())
            .field("pending_provisioning", &self.pending_provisioning.len())
            .field("certificate_trackers", &self.certificate_trackers.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::test_utils::test_transaction;
    use hyperscale_types::{
        generate_bls_keypair, verify_bls12381_v1, Bls12381G1PrivateKey, ValidatorInfo, ValidatorSet,
    };

    fn make_test_topology() -> TopologySnapshot {
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

        TopologySnapshot::new(ValidatorId(0), 1, validator_set)
    }

    fn make_test_state() -> ExecutionState {
        ExecutionState::new()
    }

    #[test]
    fn test_execution_state_creation() {
        let state = make_test_state();
        assert!(state.finalized_certificates.is_empty());
    }

    #[test]
    fn test_single_shard_execution_flow() {
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = test_transaction(1);
        let tx_hash = tx.hash();
        let block_hash = Hash::from_bytes(b"block1");

        // Block committed with transaction
        let actions = state.on_block_committed(
            &topology,
            block_hash,
            1,
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );

        // Should request execution (single-shard path) and set up wave tracking
        assert!(!actions.is_empty());
        // First action should be ExecuteTransactions
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // Transaction should be marked as executed
        assert!(state.is_executed(&tx_hash));

        // Certificate tracker should be set up for finalization
        assert!(state.certificate_trackers.contains_key(&tx_hash));
    }

    #[test]
    fn test_deduplication() {
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = test_transaction(1);
        let block_hash = Hash::from_bytes(b"block1");

        // First commit - should produce status change + execute transaction actions
        let actions1 = state.on_block_committed(
            &topology,
            block_hash,
            1,
            1000,
            ValidatorId(0),
            vec![Arc::new(tx.clone())],
        );
        assert!(!actions1.is_empty()); // Status change + execute

        // Second commit of same transaction
        let block_hash2 = Hash::from_bytes(b"block2");
        let actions2 = state.on_block_committed(
            &topology,
            block_hash2,
            2,
            2000,
            ValidatorId(0),
            vec![Arc::new(tx)],
        );

        // Should be empty (deduplicated)
        assert!(actions2.is_empty());
    }

    #[test]
    fn test_speculative_hit_before_commit() {
        // Scenario: Speculation completes BEFORE block commits (normal HIT)
        // With inline signing, votes are already sent - we just skip re-execution.
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();
        let block_hash = Hash::from_bytes(b"block1");

        // Use height past view change cooldown (default cooldown is 3 rounds)
        let height = 10;

        // Trigger speculative execution
        let actions =
            state.trigger_speculative_execution(&topology, block_hash, height, vec![tx.clone()]);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SpeculativeExecute { .. })));
        assert!(state.speculative_in_flight_txs.contains(&tx_hash));

        // Speculation completes (with inline signing, votes are already sent by runner)
        let tx_hashes = vec![tx_hash];
        let _ = state.on_speculative_execution_complete(block_hash, tx_hashes);

        // Should be marked as speculatively executed
        assert!(state.has_speculative_result(&tx_hash));
        assert!(!state.speculative_in_flight_txs.contains(&tx_hash));

        // Now block commits - should skip execution (votes already sent)
        let actions = state.on_block_committed(
            &topology,
            block_hash,
            height,
            10000,
            ValidatorId(0),
            vec![tx],
        );

        // Should NOT emit ExecuteTransactions (speculation was used, votes already sent)
        assert!(!actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // No SignExecutionResults needed - votes were signed inline
    }

    #[test]
    fn test_speculative_in_flight_at_commit() {
        // Scenario: Block commits WHILE speculation is in-flight
        // With inline signing, we just wait - votes will arrive soon.
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = Arc::new(test_transaction(1));
        let tx_hash = tx.hash();
        let block_hash = Hash::from_bytes(b"block1");

        // Use height past view change cooldown (default cooldown is 3 rounds)
        let height = 10;

        // Trigger speculative execution
        let actions =
            state.trigger_speculative_execution(&topology, block_hash, height, vec![tx.clone()]);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::SpeculativeExecute { .. })));
        assert!(state.speculative_in_flight_txs.contains(&tx_hash));

        // Block commits WHILE speculation is in-flight
        let commit_actions = state.on_block_committed(
            &topology,
            block_hash,
            height,
            10000,
            ValidatorId(0),
            vec![tx],
        );

        // Should NOT emit ExecuteTransactions (votes will arrive from speculation)
        assert!(!commit_actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // Still in-flight
        assert!(state.speculative_in_flight_txs.contains(&tx_hash));

        // Speculation completes later (votes already sent by runner)
        let tx_hashes = vec![tx_hash];
        let complete_actions = state.on_speculative_execution_complete(block_hash, tx_hashes);

        // No actions needed - votes were already sent by the runner
        assert!(complete_actions.is_empty());
        assert!(!state.speculative_in_flight_txs.contains(&tx_hash));
    }

    #[test]
    fn test_speculative_miss_no_speculation() {
        // Scenario: No speculation was triggered (MISS - normal execution)
        let mut state = make_test_state();
        let topology = make_test_topology();

        let tx = Arc::new(test_transaction(1));
        let block_hash = Hash::from_bytes(b"block1");

        // Block commits without any speculation
        let actions =
            state.on_block_committed(&topology, block_hash, 1, 1000, ValidatorId(0), vec![tx]);

        // Should emit ExecuteTransactions (no speculation to use)
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));
    }

    // ========================================================================
    // Crypto Verification Tests - Using real BLS signatures
    // ========================================================================

    #[test]
    fn test_execution_vote_with_real_bls_signature() {
        use hyperscale_test_helpers::{fixtures, TestCommittee};

        let committee = TestCommittee::new(4, 42);
        let tx_hash = Hash::from_bytes(b"test_tx");
        let receipt_hash = Hash::from_bytes(b"state_root");
        let shard = ShardGroupId(0);

        // Create a properly signed execution vote
        let vote = fixtures::make_signed_execution_vote(
            &committee,
            0, // voter index
            tx_hash,
            receipt_hash,
            shard,
            true,
        );

        // Verify the signature using the signing_message method
        let message = vote.signing_message();
        let valid = verify_bls12381_v1(&message, committee.public_key(0), &vote.signature);
        assert!(valid, "Execution vote signature should verify");

        // Verify with wrong key fails
        let invalid = verify_bls12381_v1(&message, committee.public_key(1), &vote.signature);
        assert!(!invalid, "Execution vote should NOT verify with wrong key");
    }

    #[test]
    fn test_execution_certificate_with_real_bls_signatures() {
        use hyperscale_test_helpers::{fixtures, TestCommittee};

        let committee = TestCommittee::new(4, 42);
        let tx_hash = Hash::from_bytes(b"test_tx");
        let receipt_hash = Hash::from_bytes(b"commitment");
        let shard = ShardGroupId(0);

        // Create an execution certificate with real aggregated signatures
        let cert = fixtures::make_signed_execution_certificate(
            &committee,
            &[0, 1, 2], // 3 voters
            tx_hash,
            receipt_hash,
            shard,
            true,
        );

        // Verify using the certificate's signing_message
        let message = cert.signing_message();

        // Get signer public keys based on bitfield
        let signer_keys: Vec<_> = cert
            .signers
            .set_indices()
            .map(|idx| *committee.public_key(idx))
            .collect();

        // Aggregate public keys (what the runner does)
        let aggregated_pk =
            Bls12381G1PublicKey::aggregate(&signer_keys, true).expect("Aggregation should succeed");

        // Verify the aggregated signature
        let valid = hyperscale_types::verify_bls12381_v1(
            &message,
            &aggregated_pk,
            &cert.aggregated_signature,
        );
        assert!(valid, "Execution certificate signature should verify");
    }

    #[test]
    fn test_batch_verify_execution_votes_different_messages() {
        use hyperscale_test_helpers::TestCommittee;

        let committee = TestCommittee::new(4, 42);
        let shard = ShardGroupId(0);

        // Different transactions = different messages
        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");
        let tx3 = Hash::from_bytes(b"tx3");
        let root = Hash::from_bytes(b"root");

        let msg1 = hyperscale_types::exec_vote_message(&tx1, &root, shard, true);
        let msg2 = hyperscale_types::exec_vote_message(&tx2, &root, shard, true);
        let msg3 = hyperscale_types::exec_vote_message(&tx3, &root, shard, true);

        let sig1 = committee.keypair(0).sign_v1(&msg1);
        let sig2 = committee.keypair(1).sign_v1(&msg2);
        let sig3 = committee.keypair(2).sign_v1(&msg3);

        let messages: Vec<&[u8]> = vec![&msg1, &msg2, &msg3];
        let signatures = vec![sig1, sig2, sig3];
        let pubkeys: Vec<_> = (0..3).map(|i| *committee.public_key(i)).collect();

        // Batch verify with different messages (what dispatch_execution_vote_verifications does)
        let results =
            hyperscale_types::batch_verify_bls_different_messages(&messages, &signatures, &pubkeys);

        assert_eq!(
            results,
            vec![true, true, true],
            "All signatures should verify"
        );
    }

    #[test]
    fn test_batch_verify_execution_votes_partial_failure() {
        use hyperscale_test_helpers::TestCommittee;

        let committee = TestCommittee::new(4, 42);
        let shard = ShardGroupId(0);

        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");
        let root = Hash::from_bytes(b"root");

        let msg1 = hyperscale_types::exec_vote_message(&tx1, &root, shard, true);
        let msg2 = hyperscale_types::exec_vote_message(&tx2, &root, shard, true);

        // First is valid, second is signed with wrong key
        let sig1 = committee.keypair(0).sign_v1(&msg1);
        let sig2 = committee.keypair(3).sign_v1(&msg2); // Wrong key! Should be keypair 1

        let messages: Vec<&[u8]> = vec![&msg1, &msg2];
        let signatures = vec![sig1, sig2];
        let pubkeys = vec![
            *committee.public_key(0),
            *committee.public_key(1), // Verifying with key 1
        ];

        let results =
            hyperscale_types::batch_verify_bls_different_messages(&messages, &signatures, &pubkeys);

        assert_eq!(
            results,
            vec![true, false],
            "Second signature should fail verification"
        );
    }
}
