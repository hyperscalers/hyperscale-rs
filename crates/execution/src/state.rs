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
//! on the same receipt hash, an execution certificate is created and broadcast to
//! remote participating shards (local peers form it independently).
//!
//! ## Phase 5: Finalization
//! Validators collect shard execution proofs from all participating shards. When all
//! proofs are received, a TransactionCertificate is created.

use hyperscale_core::{Action, CrossShardExecutionRequest, ProtocolEvent, ProvisionRequest};
use hyperscale_types::{
    AbortReason, BlockHeight, Bls12381G1PublicKey, DatabaseUpdates, ExecutionResult, ExecutionVote,
    Hash, LedgerTransactionReceipt, ProvisionBatch, ReceiptBundle, RoutableTransaction,
    ShardExecutionProof, ShardGroupId, StateProvision, TopologySnapshot, TransactionCertificate,
    TransactionDecision, TxExecutionOutcome, TxOutcome, ValidatorId, WaveId,
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

use crate::accumulator::ExecutionAccumulator;
use crate::trackers::{CertificateTracker, VoteTracker};

/// Data returned when a wave completes (all txs executed).
///
/// The state machine produces this; the io_loop uses it to sign the execution vote
/// and broadcast (since the state machine doesn't hold the signing key).
#[derive(Debug)]
pub struct CompletionData {
    /// Block this wave belongs to.
    pub block_hash: Hash,
    /// Block height.
    pub block_height: u64,
    /// Wave identifier.
    pub wave_id: WaveId,
    /// Merkle root over per-tx outcome leaves.
    pub receipt_root: Hash,
    /// Per-tx outcomes in wave order.
    pub tx_outcomes: Vec<hyperscale_types::TxOutcome>,
}

/// A cross-shard transaction registration for provision tracking.
///
/// Returned by [`ExecutionState::on_block_committed`] as structured data
/// instead of `Action::Continuation` events.
#[derive(Debug, Clone)]
pub struct CrossShardRegistration {
    /// Hash of the cross-shard transaction.
    pub tx_hash: Hash,
    /// Remote shards this transaction needs provisions from.
    pub required_shards: BTreeSet<ShardGroupId>,
    /// Block height when the transaction was committed.
    pub committed_height: BlockHeight,
}

/// Output from [`ExecutionState::on_block_committed`].
///
/// Separates actions from cross-shard registrations so the orchestrator
/// can process registrations before forwarding actions.
pub struct BlockCommittedOutput {
    /// Actions to dispatch (execution, provisioning, etc.).
    pub actions: Vec<Action>,
    /// Cross-shard registrations for the provision coordinator.
    pub cross_shard_registrations: Vec<CrossShardRegistration>,
}

/// A finalized certificate with its co-located DatabaseUpdates.
///
/// A finalized transaction certificate ready for block inclusion.
///
/// DatabaseUpdates are NOT stored here — they are derived from the receipt
/// (the quorum-agreed artifact) at state root computation time. This ensures
/// all validators produce identical updates regardless of local execution timing.
#[derive(Debug, Clone)]
pub struct FinalizedCertEntry {
    pub certificate: Arc<TransactionCertificate>,
    #[allow(dead_code)] // Used for stale-entry pruning in future
    pub committed_height: u64,
}

/// Execution memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecutionMemoryStats {
    pub receipts_emitted: usize,
    pub finalized_certificates: usize,
    pub pending_provisioning: usize,
    pub accumulators: usize,
    pub vote_trackers: usize,
    pub early_votes: usize,
    pub certificate_trackers: usize,
    pub expected_exec_certs: usize,
    /// Speculative provision preparations in-flight.
    pub speculative_provision_in_flight: usize,
    /// Cached speculative provision results.
    pub speculative_provision_results: usize,
    /// Blocks committed while speculative provisions were in-flight.
    pub pending_provision_commits: usize,
}

/// Execution state machine.
///
/// Handles transaction execution after blocks are committed.
pub struct ExecutionState {
    /// Current time.
    now: Duration,

    /// Tracks transaction hashes whose receipts have been emitted via
    /// `StoreReceiptBundles`. Used as a gate for deferred TC creation —
    /// TC formation requires that the receipt exists so state root verification
    /// can later derive DatabaseUpdates from it.
    receipts_emitted: HashSet<Hash>,

    /// Finalized transaction certificates ready for block inclusion.
    /// Uses BTreeMap for deterministic iteration order.
    finalized_certificates: BTreeMap<Hash, FinalizedCertEntry>,

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
    /// Execution accumulators: collect per-tx execution results within each wave.
    /// Keyed by (block_hash, wave_id) to handle multiple blocks in flight.
    accumulators: HashMap<(Hash, WaveId), ExecutionAccumulator>,

    /// Execution vote trackers: collect execution votes from other validators.
    /// Keyed by (block_hash, wave_id). Only created on the wave leader.
    vote_trackers: HashMap<(Hash, WaveId), VoteTracker>,

    /// Waves that have a canonical EC (aggregated by leader, or received from leader).
    /// Used to stop re-voting in `scan_complete_waves`. Replaces the old check of
    /// "VoteTracker absent" now that only wave leaders create VoteTrackers.
    waves_with_ec: HashSet<(Hash, WaveId)>,

    /// Tx → wave assignment lookup for the current block.
    /// Maps tx_hash → (block_hash, wave_id).
    wave_assignments: HashMap<Hash, (Hash, WaveId)>,

    /// Early execution votes that arrived before tracking started.
    /// Keyed by (block_hash, wave_id). Only buffered for the wave leader.
    early_votes: HashMap<(Hash, WaveId), Vec<ExecutionVote>>,

    // ═══════════════════════════════════════════════════════════════════════
    // Cross-shard state (Phase 5: Finalization)
    // ═══════════════════════════════════════════════════════════════════════
    /// Certificate trackers for cross-shard transactions.
    /// Maps tx_hash -> (CertificateTracker, height_when_created) for stale-entry pruning.
    certificate_trackers: HashMap<Hash, (CertificateTracker, u64)>,

    // ═══════════════════════════════════════════════════════════════════════
    // Early arrivals (before tracking starts)
    // ═══════════════════════════════════════════════════════════════════════
    /// Execution results that arrived before the wave was assigned.
    /// Maps tx_hash -> TxExecutionOutcome. Replayed during assign_waves.
    early_execution_results: HashMap<Hash, TxExecutionOutcome>,

    /// ProvisioningComplete events that arrived before the block was committed.
    /// This can happen when provisions reach quorum before we've seen the block.
    /// Maps tx_hash -> (provisions, first_arrival_height) for cleanup of stale entries.
    early_provisioning_complete: HashMap<Hash, (Vec<StateProvision>, u64)>,

    /// Proofs that arrived before tracking started.
    /// Tracks (shard_id, proof) pairs with first_arrival_height for cleanup of stale entries.
    early_certificates: HashMap<Hash, (Vec<(ShardGroupId, ShardExecutionProof)>, u64)>,

    /// Transactions whose certificate tracker completed but local execution hasn't
    /// finished yet. TC creation is deferred until `on_execution_batch_completed`
    /// populates `receipts_emitted` for these tx hashes.
    deferred_tc_creations: HashSet<Hash>,

    // ═══════════════════════════════════════════════════════════════════════
    // Execution Certificate Cache (for fallback serving)
    // ═══════════════════════════════════════════════════════════════════════
    // ═══════════════════════════════════════════════════════════════════════
    // Expected Execution Certificate Tracking (Fallback Detection)
    // ═══════════════════════════════════════════════════════════════════════
    /// Expected execution certificates from remote shards.
    /// Populated when remote block headers with waves targeting our shard are seen.
    /// Cleared when the matching cert is received and verified.
    /// After timeout, triggers `RequestMissingExecutionCert` fallback.
    expected_exec_certs: HashMap<(ShardGroupId, u64, WaveId), ExpectedExecCert>,

    /// Fulfilled execution cert keys — prevents late-arriving duplicate headers
    /// from re-registering expectations after certs have already been received.
    /// Maps (source_shard, block_height, wave_id) → local_height_when_fulfilled
    /// for age-based pruning using local time.
    fulfilled_exec_certs: HashMap<(ShardGroupId, u64, WaveId), u64>,

    // ═══════════════════════════════════════════════════════════════════════
    // Speculative Provision State
    // ═══════════════════════════════════════════════════════════════════════
    /// Block hashes with in-flight speculative provision prep.
    speculative_provision_in_flight: HashSet<Hash>,
    /// Cached speculative provision results, keyed by block_hash.
    speculative_provision_results: HashMap<Hash, CachedProvisions>,
    /// When commit arrives while speculation is in-flight, store full context
    /// so we can emit SendProvisions or fall back to FetchAndBroadcastProvisions.
    pending_provision_commits: HashMap<Hash, PendingProvisionCommit>,
}

impl Default for ExecutionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks an expected execution certificate that hasn't arrived yet.
#[derive(Debug, Clone)]
struct ExpectedExecCert {
    /// Hash of the remote block that declared these waves.
    /// Used to compute the wave leader for preferred-peer fetch ordering.
    block_hash: Hash,
    /// Local committed height when we first learned about this expected cert.
    discovered_at: u64,
    /// Local committed height when we last sent a fallback request, if any.
    /// `None` means never requested. Allows periodic re-requests with cooldown.
    last_requested_at: Option<u64>,
}

/// Number of blocks to wait before the first fallback request.
const EXEC_CERT_FALLBACK_TIMEOUT_BLOCKS: u64 = 10;

/// Number of blocks between repeated fallback requests for the same cert.
const EXEC_CERT_RETRY_INTERVAL_BLOCKS: u64 = 20;

/// Per-shard recipient lists for provision broadcasting.
type ShardRecipients = HashMap<ShardGroupId, Vec<ValidatorId>>;

/// Cached provision batches from speculative preparation.
struct CachedProvisions {
    batches: Vec<(ShardGroupId, ProvisionBatch, Vec<ValidatorId>)>,
    block_timestamp: u64,
}

/// Context stored when a block commits while speculative provisions are in-flight.
/// Contains everything needed to fall back to `FetchAndBroadcastProvisions` if
/// speculation returns empty.
struct PendingProvisionCommit {
    block_timestamp: u64,
    requests: Vec<ProvisionRequest>,
    source_shard: ShardGroupId,
    block_height: BlockHeight,
    shard_recipients: ShardRecipients,
}

impl ExecutionState {
    /// Create a new execution state machine.
    pub fn new() -> Self {
        Self {
            now: Duration::ZERO,
            receipts_emitted: HashSet::new(),
            finalized_certificates: BTreeMap::new(),
            committed_height: 0,
            pending_provisioning: HashMap::new(),
            accumulators: HashMap::new(),
            vote_trackers: HashMap::new(),
            waves_with_ec: HashSet::new(),
            wave_assignments: HashMap::new(),
            early_votes: HashMap::new(),
            certificate_trackers: HashMap::new(),
            early_execution_results: HashMap::new(),
            early_provisioning_complete: HashMap::new(),
            early_certificates: HashMap::new(),
            deferred_tc_creations: HashSet::new(),
            expected_exec_certs: HashMap::new(),
            fulfilled_exec_certs: HashMap::new(),
            speculative_provision_in_flight: HashSet::new(),
            speculative_provision_results: HashMap::new(),
            pending_provision_commits: HashMap::new(),
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
    // Certificate Updates (from finalized_certificates)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Collect per-certificate database updates for proposal building.
    ///
    /// Check if a finalized certificate exists for a transaction.
    ///
    /// Used by BFT pending block receipt tracking.
    pub fn has_finalized_certificate(&self, tx_hash: &Hash) -> bool {
        self.finalized_certificates.contains_key(tx_hash)
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

    /// Set up execution accumulators and vote trackers for a newly committed block.
    ///
    /// Creates a `ExecutionAccumulator` and `VoteTracker` per wave, and records
    /// the tx → wave mapping for later result routing.
    ///
    /// Returns any early execution votes that arrived before tracking was set up,
    /// so the caller can replay them through `on_execution_vote()`.
    fn setup_execution_tracking(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: Hash,
        block_height: u64,
        transactions: &[Arc<RoutableTransaction>],
    ) -> Vec<ExecutionVote> {
        let waves = self.assign_waves(topology, transactions);
        let quorum = topology.local_quorum_threshold();
        let mut votes_to_replay = Vec::new();

        let local_vid = topology.local_validator_id();
        let local_committee = topology.local_committee();

        for (wave_id, txs) in waves {
            let key = (block_hash, wave_id.clone());

            // Record tx → wave assignments
            for (tx_hash, _) in &txs {
                self.wave_assignments
                    .insert(*tx_hash, (block_hash, wave_id.clone()));
            }

            // Create accumulator
            let accumulator =
                ExecutionAccumulator::new(wave_id.clone(), block_hash, block_height, txs);
            self.accumulators.insert(key.clone(), accumulator);

            // Only the wave leader creates a VoteTracker and aggregates votes.
            // Non-leaders receive the canonical EC from the wave leader via
            // on_wave_certificate → on_certificate_verified.
            let leader = hyperscale_types::wave_leader(&block_hash, &wave_id, local_committee);
            if local_vid == leader {
                let tracker = VoteTracker::new(wave_id, block_hash, quorum);
                self.vote_trackers.insert(key.clone(), tracker);

                // Collect early execution votes for caller to replay through on_execution_vote()
                if let Some(early_votes) = self.early_votes.remove(&key) {
                    tracing::debug!(
                        block_hash = ?block_hash,
                        wave = %key.1,
                        count = early_votes.len(),
                        "Replaying early execution votes"
                    );
                    votes_to_replay.extend(early_votes);
                }
            } else {
                // Non-leader: discard any buffered votes (we won't aggregate them)
                self.early_votes.remove(&key);
            }
        }

        // Replay any early execution results that arrived before wave setup.
        let mut early_tx_hashes: Vec<Hash> = self
            .early_execution_results
            .keys()
            .filter(|h| self.wave_assignments.contains_key(h))
            .copied()
            .collect();
        early_tx_hashes.sort();
        if !early_tx_hashes.is_empty() {
            tracing::debug!(
                block_hash = ?block_hash,
                count = early_tx_hashes.len(),
                "Replaying early execution results into accumulators"
            );
            for tx_hash in early_tx_hashes {
                if let Some(outcome) = self.early_execution_results.remove(&tx_hash) {
                    if let Some(wave_key) = self.wave_assignments.get(&tx_hash).cloned() {
                        if let Some(acc) = self.accumulators.get_mut(&wave_key) {
                            acc.record_result(tx_hash, outcome);
                        }
                    }
                }
            }
        }

        tracing::debug!(
            block_hash = ?block_hash,
            wave_count = self.accumulators.iter()
                .filter(|((bh, _), _)| *bh == block_hash)
                .count(),
            "Wave tracking set up for block"
        );

        votes_to_replay
    }

    /// Record a transaction execution result into the appropriate execution accumulator.
    ///
    /// Updates the accumulator silently. Votes are NOT emitted here — they are
    /// emitted during the block commit wave scan (`scan_complete_waves`), ensuring
    /// deterministic voting at each consensus height.
    pub fn record_execution_result(&mut self, tx_hash: Hash, outcome: TxExecutionOutcome) {
        let Some(wave_key) = self.wave_assignments.get(&tx_hash).cloned() else {
            // Wave not assigned yet (e.g. execution completed before
            // on_block_committed created the wave). Buffer for replay.
            self.early_execution_results.insert(tx_hash, outcome);
            return;
        };

        let Some(accumulator) = self.accumulators.get_mut(&wave_key) else {
            return;
        };

        accumulator.record_result(tx_hash, outcome);
    }

    /// Record an abort intent into the appropriate execution accumulator.
    ///
    /// Record an abort intent into the appropriate execution accumulator.
    ///
    /// Abort intents are consensus-committed (deterministic) and ALWAYS override
    /// async execution results. This ensures all validators converge to the same
    /// receipt_root regardless of execution timing.
    ///
    /// Updates the accumulator silently. Votes are NOT emitted here — they are
    /// emitted during the block commit wave scan (`scan_complete_waves`).
    ///
    /// A missing wave assignment means the transaction already reached terminal
    /// state (TC committed) — the abort intent is a harmless late arrival.
    pub fn record_abort_intent(&mut self, tx_hash: Hash, reason: AbortReason) {
        let Some(wave_key) = self.wave_assignments.get(&tx_hash).cloned() else {
            tracing::debug!(
                tx_hash = %tx_hash,
                ?reason,
                committed_height = self.committed_height,
                "Abort intent: no wave assignment (already cleaned up)"
            );
            return;
        };

        let Some(accumulator) = self.accumulators.get_mut(&wave_key) else {
            tracing::debug!(
                tx_hash = %tx_hash,
                wave = %wave_key.1,
                "Abort intent: no accumulator for wave"
            );
            return;
        };

        let outcome = TxExecutionOutcome::Aborted { reason };
        accumulator.record_abort(tx_hash, outcome);
    }

    /// Scan all incomplete waves and return completion data for any that are ready.
    ///
    /// Called at each block commit AFTER abort intents have been processed.
    /// This is the SINGLE path to voting — votes are never emitted from
    /// `record_execution_result` or `record_abort_intent`.
    ///
    /// Returns a `CompletionData` for each wave that is complete at this height.
    /// Waves that already had an EC formed (vote tracker removed) are skipped.
    pub fn scan_complete_waves(&self) -> Vec<CompletionData> {
        let mut completions = Vec::new();

        for (key, accumulator) in &self.accumulators {
            // Skip waves that already have a canonical EC (aggregated by
            // wave leader, or received from wave leader).
            if self.waves_with_ec.contains(key) {
                continue;
            }

            if !accumulator.is_complete() {
                continue;
            }

            let Some((receipt_root, tx_outcomes)) = accumulator.build_data() else {
                continue;
            };

            completions.push(CompletionData {
                block_hash: accumulator.block_hash(),
                block_height: accumulator.block_height(),
                wave_id: accumulator.wave_id().clone(),
                receipt_root,
                tx_outcomes,
            });
        }

        // Sort for deterministic ordering (accumulators is a HashMap).
        completions.sort_by(|a, b| (&a.block_hash, &a.wave_id).cmp(&(&b.block_hash, &b.wave_id)));

        completions
    }

    /// Process a completed execution batch: build receipt bundles, update cache, record outcomes.
    ///
    /// Moves receipt-bundle construction and cache insertion out of the node orchestrator.
    pub fn on_execution_batch_completed(
        &mut self,
        results: Vec<ExecutionResult>,
        tx_outcomes: Vec<TxOutcome>,
    ) -> Vec<Action> {
        let mut bundles: Vec<ReceiptBundle> = Vec::with_capacity(results.len());

        for result in results {
            let tx_hash = result.tx_hash;
            bundles.push(ReceiptBundle {
                tx_hash,
                ledger_receipt: Arc::new(result.ledger_receipt),
                local_execution: Some(result.local_execution),
            });
            self.receipts_emitted.insert(tx_hash);
        }

        // Dispatch receipt storage (fire-and-forget, off main thread)
        let mut actions: Vec<Action> = Vec::new();
        if !bundles.is_empty() {
            tracing::debug!(bundle_count = bundles.len(), "Emitting StoreReceiptBundles");
            actions.push(Action::StoreReceiptBundles { bundles });
        } else {
            tracing::warn!(
                results_count = 0,
                "ExecutionBatchCompleted produced ZERO receipt bundles"
            );
        }

        // Drain deferred TC creations now that receipts are available.
        // A deferred TC means the certificate tracker completed (all shard proofs
        // collected) before local execution finished. Now the receipt is emitted.
        let deferred: Vec<Hash> = self
            .deferred_tc_creations
            .iter()
            .filter(|h| self.receipts_emitted.contains(h))
            .copied()
            .collect();
        for tx_hash in deferred {
            self.deferred_tc_creations.remove(&tx_hash);
            let Some((tracker, _)) = self.certificate_trackers.get_mut(&tx_hash) else {
                continue;
            };
            let Some(tx_cert) = tracker.create_tx_certificate() else {
                continue;
            };
            let accepted = tx_cert.decision == TransactionDecision::Accept;
            tracing::debug!(
                tx_hash = %tx_hash,
                accepted,
                "Deferred TC creation — receipt now available"
            );

            actions.push(Action::PersistTransactionCertificate {
                certificate: tx_cert.clone(),
            });

            self.receipts_emitted.remove(&tx_hash);
            self.finalized_certificates.insert(
                tx_hash,
                FinalizedCertEntry {
                    certificate: Arc::new(tx_cert),
                    committed_height: self.committed_height,
                },
            );

            self.certificate_trackers.remove(&tx_hash);

            actions.push(Action::Continuation(ProtocolEvent::TransactionExecuted {
                tx_hash,
                accepted,
            }));
        }

        // Record outcomes into execution accumulators silently.
        // Votes are emitted during the block commit wave scan, not here.
        for wr in tx_outcomes {
            self.record_execution_result(wr.tx_hash, wr.outcome);
        }

        actions
    }

    /// Overwrite stored receipts for transactions the EC declares as aborted.
    ///
    /// The EC is the canonical source of truth for abort decisions. Canonical
    /// execution may have already stored a success receipt before
    /// the abort was decided at the aggregated vote_height. This replaces those
    /// stale receipts with `LedgerTransactionReceipt::failure()` so that any
    /// downstream consumer (sync, RPC, state root) sees a consistent abort.
    ///
    /// Only processes the LOCAL shard's EC — remote shard ECs don't produce
    /// local receipts.
    fn overwrite_aborted_receipts(
        &self,
        certificate: &hyperscale_types::ExecutionCertificate,
    ) -> Vec<Action> {
        let abort_bundles: Vec<ReceiptBundle> = certificate
            .tx_outcomes
            .iter()
            .filter(|o| o.is_aborted())
            .map(|o| ReceiptBundle {
                tx_hash: o.tx_hash,
                ledger_receipt: Arc::new(LedgerTransactionReceipt::failure()),
                local_execution: None,
            })
            .collect();

        if abort_bundles.is_empty() {
            return vec![];
        }

        tracing::debug!(
            block_hash = ?certificate.block_hash,
            wave = %certificate.wave_id,
            abort_count = abort_bundles.len(),
            "Overwriting receipts for EC-aborted transactions"
        );

        vec![Action::StoreReceiptBundles {
            bundles: abort_bundles,
        }]
    }

    /// Scan complete waves and emit `SignAndSendExecutionVote` actions.
    ///
    /// This is the SINGLE path to execution voting. Call after abort intents
    /// have been processed so accumulator state is deterministic at this height.
    /// Each vote is targeted to the wave leader (N→1 routing).
    pub fn emit_vote_actions(&self, topology: &TopologySnapshot, vote_height: u64) -> Vec<Action> {
        let local_committee = topology.local_committee();
        self.scan_complete_waves()
            .into_iter()
            .map(|completion| {
                let target = hyperscale_types::wave_leader(
                    &completion.block_hash,
                    &completion.wave_id,
                    local_committee,
                );
                Action::SignAndSendExecutionVote {
                    block_hash: completion.block_hash,
                    block_height: completion.block_height,
                    vote_height,
                    wave_id: completion.wave_id,
                    receipt_root: completion.receipt_root,
                    tx_outcomes: completion.tx_outcomes,
                    target,
                }
            })
            .collect()
    }

    /// Process committed certificates: cross-check receipt hashes, remove finalized state.
    ///
    /// The caller is responsible for any BFT-side cleanup (e.g. `bft.remove_committed_transaction`).
    pub fn on_certificates_committed(&mut self, certificates: &[Arc<TransactionCertificate>]) {
        for cert in certificates {
            self.remove_finalized_certificate(&cert.transaction_hash, cert.decision);
        }
    }

    /// Record abort intents from a committed block into execution accumulators.
    ///
    /// Abort intents override async execution results to ensure validator convergence.
    pub fn record_abort_intents(&mut self, intents: &[hyperscale_types::AbortIntent]) {
        for intent in intents {
            self.record_abort_intent(intent.tx_hash, intent.reason.clone());
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Wave Vote Handling
    // ═══════════════════════════════════════════════════════════════════════════

    /// Handle an execution vote received from another validator (or self).
    ///
    /// Only the wave leader aggregates votes. Non-leaders discard them.
    pub fn on_execution_vote(
        &mut self,
        topology: &TopologySnapshot,
        vote: ExecutionVote,
    ) -> Vec<Action> {
        let key = (vote.block_hash, vote.wave_id.clone());
        let validator_id = vote.validator;

        // Check if we're tracking this wave (only wave leaders have VoteTrackers)
        if !self.vote_trackers.contains_key(&key) {
            // If we have an accumulator for this wave but no VoteTracker,
            // we're a non-leader — discard the vote.
            if self.accumulators.contains_key(&key) {
                return vec![];
            }
            // No accumulator yet — block hasn't committed. Buffer for the
            // wave leader case (will be discarded in setup if non-leader).
            self.early_votes.entry(key).or_default().push(vote);
            return vec![];
        }

        // Skip verification for our own vote
        if validator_id == topology.local_validator_id() {
            return self.handle_verified_vote(topology, vote);
        }

        // Get public key for signature verification
        let Some(public_key) = topology.public_key(validator_id) else {
            tracing::warn!(
                validator = validator_id.0,
                "Unknown validator for execution vote"
            );
            return vec![];
        };

        let voting_power = topology.voting_power(validator_id).unwrap_or(0);

        let tracker = self.vote_trackers.get_mut(&key).unwrap();

        // buffer_unverified_vote handles dedup per (validator, vote_height).
        // Same validator can vote at multiple heights (round voting).
        if !tracker.buffer_unverified_vote(vote, public_key, voting_power) {
            return vec![];
        }

        self.maybe_trigger_vote_verification(key)
    }

    /// Check if we should trigger batch verification for a wave's votes.
    fn maybe_trigger_vote_verification(&mut self, key: (Hash, WaveId)) -> Vec<Action> {
        let Some(tracker) = self.vote_trackers.get_mut(&key) else {
            return vec![];
        };

        if !tracker.should_trigger_verification() {
            return vec![];
        }

        let votes = tracker.take_unverified_votes();
        if votes.is_empty() {
            return vec![];
        }

        tracing::debug!(
            block_hash = ?key.0,
            wave = %key.1,
            vote_count = votes.len(),
            "Dispatching execution vote batch verification"
        );
        vec![Action::VerifyAndAggregateExecutionVotes {
            wave_id: key.1,
            block_hash: key.0,
            votes,
        }]
    }

    /// Handle a verified execution vote (own vote or already-verified).
    fn handle_verified_vote(
        &mut self,
        topology: &TopologySnapshot,
        vote: ExecutionVote,
    ) -> Vec<Action> {
        let key = (vote.block_hash, vote.wave_id.clone());
        let voting_power = topology.voting_power(vote.validator).unwrap_or(0);

        let Some(tracker) = self.vote_trackers.get_mut(&key) else {
            return vec![];
        };

        tracker.add_verified_vote(vote, voting_power);

        let mut actions = self.check_vote_quorum(topology, key.clone());
        actions.extend(self.maybe_trigger_vote_verification(key));
        actions
    }

    /// Handle batch execution vote verification completed.
    pub fn on_votes_verified(
        &mut self,
        topology: &TopologySnapshot,
        wave_id: WaveId,
        block_hash: Hash,
        verified_votes: Vec<(ExecutionVote, u64)>,
    ) -> Vec<Action> {
        let key = (block_hash, wave_id);

        let Some(tracker) = self.vote_trackers.get_mut(&key) else {
            return vec![];
        };

        tracker.on_verification_complete();

        for (vote, power) in verified_votes {
            tracker.add_verified_vote(vote, power);
        }

        // Warn if we have enough total power for quorum but it's split
        // across multiple receipt roots — this means validators disagree
        // on execution results.
        if tracker.check_quorum().is_none()
            && tracker.total_verified_power() >= topology.local_quorum_threshold()
            && tracker.distinct_receipt_root_count() > 1
        {
            let summary = tracker.receipt_root_power_summary();
            tracing::warn!(
                block_hash = ?key.0,
                wave = %key.1,
                receipt_root_split = ?summary,
                quorum = topology.local_quorum_threshold(),
                "Execution vote quorum blocked: receipt roots are split across validators"
            );
        }

        let mut actions = self.check_vote_quorum(topology, key.clone());
        actions.extend(self.maybe_trigger_vote_verification(key));
        actions
    }

    /// Check if quorum is reached for a wave's votes.
    fn check_vote_quorum(
        &mut self,
        topology: &TopologySnapshot,
        key: (Hash, WaveId),
    ) -> Vec<Action> {
        let Some(tracker) = self.vote_trackers.get_mut(&key) else {
            return vec![];
        };

        let Some((receipt_root, vote_height, _total_power)) = tracker.check_quorum() else {
            return vec![];
        };

        tracing::info!(
            block_hash = ?key.0,
            wave = %key.1,
            vote_height,
            "Execution vote quorum reached — aggregating certificate"
        );

        let votes = tracker.take_votes(&receipt_root, vote_height);
        let committee = topology.local_committee().to_vec();

        // Remove the vote tracker — this EC is the shard's final answer.
        // Mark wave as having an EC to stop re-voting in scan_complete_waves.
        self.vote_trackers.remove(&key);
        self.waves_with_ec.insert(key.clone());

        tracing::debug!(
            block_hash = ?key.0,
            wave = %key.1,
            votes = votes.len(),
            "Delegating BLS aggregation to crypto pool"
        );

        // tx_outcomes are extracted from votes by the aggregation handler
        // (all quorum votes carry identical outcomes).
        vec![Action::AggregateExecutionCertificate {
            wave_id: key.1,
            shard: topology.local_shard(),
            receipt_root,
            votes,
            committee,
        }]
    }

    /// Handle execution certificate aggregation completed.
    ///
    /// Called when the crypto pool finishes BLS aggregation for a wave's votes.
    /// Broadcasts the execution cert to remote shards, then extracts per-tx outcomes
    /// and feeds them to per-tx CertificateTrackers for finalization.
    pub fn on_certificate_aggregated(
        &mut self,
        topology: &TopologySnapshot,
        wave_id: WaveId,
        certificate: hyperscale_types::ExecutionCertificate,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let local_vid = topology.local_validator_id();
        let block_hash = certificate.block_hash;

        // The wave_id IS the set of remote shards — no need to look up the
        // accumulator (which may have been pruned by the time the cert is
        // aggregated, especially with many shards where provision flow is slower).
        let remote_shards: Vec<ShardGroupId> = wave_id.0.iter().copied().collect();

        let certificate = Arc::new(certificate);

        // Cache the cert in io_loop for fallback serving — any node can serve
        // requests from remote shards if the wave leader fails.
        actions.push(Action::PersistExecutionCertificate {
            certificate: Arc::clone(&certificate),
        });

        // The wave leader broadcasts the EC to:
        // 1. Local peers — so they receive the canonical EC (same path as remote ECs)
        // 2. Remote shard validators — for cross-shard finalization
        {
            // Broadcast to local peers (all local committee minus self)
            let local_peers: Vec<ValidatorId> = topology
                .local_committee()
                .iter()
                .copied()
                .filter(|&v| v != local_vid)
                .collect();
            if !local_peers.is_empty() {
                actions.push(Action::BroadcastExecutionCertificate {
                    shard: topology.local_shard(),
                    certificate: Arc::clone(&certificate),
                    recipients: local_peers,
                });
            }

            // Broadcast to remote shard validators
            for target_shard in &remote_shards {
                let recipients: Vec<ValidatorId> = topology
                    .committee_for_shard(*target_shard)
                    .iter()
                    .copied()
                    .filter(|&v| v != local_vid)
                    .collect();
                actions.push(Action::BroadcastExecutionCertificate {
                    shard: *target_shard,
                    certificate: Arc::clone(&certificate),
                    recipients,
                });
            }
        }

        tracing::debug!(
            ?block_hash,
            wave = %wave_id,
            tx_count = certificate.tx_outcomes.len(),
            remote_shards = remote_shards.len(),
            "Wave leader broadcasting EC to local peers + remote shards"
        );

        // The EC is canonical — if it says a tx is aborted, the stored receipt
        // must reflect that. Canonical execution may have stored
        // a success receipt before the abort was decided. Overwrite now.
        actions.extend(self.overwrite_aborted_receipts(&certificate));

        // Feed each tx's outcome to per-tx CertificateTracker for finalization.
        // Deferred/aborted txs (Hash::ZERO) are filtered by handle_certificate_internal.
        let ec_hash = certificate.canonical_hash();
        for outcome in &certificate.tx_outcomes {
            let proof = outcome.to_shard_proof(ec_hash);

            actions.extend(self.handle_certificate_internal(
                topology,
                outcome.tx_hash,
                certificate.shard_group_id,
                proof,
            ));
        }

        actions
    }

    /// Handle an execution certificate received from another validator.
    ///
    /// This handles ECs from both:
    /// - The wave leader (local shard EC broadcast to local peers)
    /// - Remote shards (cross-shard EC for finalization)
    ///
    /// A execution cert covers many txs. Each tx is handled independently:
    /// - If tracker exists → needs verification, then feed proof
    /// - If already finalized → skip
    /// - If no tracker yet → buffer as early proof for later replay
    ///
    /// Delegates BLS signature verification to the crypto pool before processing
    /// any tracked txs. Buffered txs are replayed when their block commits.
    pub fn on_wave_certificate(
        &mut self,
        topology: &TopologySnapshot,
        cert: hyperscale_types::ExecutionCertificate,
    ) -> Vec<Action> {
        let shard = cert.shard_group_id;
        let current_height = self.committed_height;

        // Clear expected cert tracking and mark as fulfilled so late-arriving
        // duplicate headers don't re-register the expectation.
        let key = (shard, cert.block_height, cert.wave_id.clone());
        self.expected_exec_certs.remove(&key);
        self.fulfilled_exec_certs.insert(key, self.committed_height);

        // Buffer proofs for txs that don't have trackers yet (block not committed).
        // Skip txs that are already finalized.
        // If ANY tx has a tracker, we need to verify the execution cert signature.
        let ec_hash = cert.canonical_hash();
        let mut needs_verification = false;
        for outcome in &cert.tx_outcomes {
            if self.certificate_trackers.contains_key(&outcome.tx_hash) {
                needs_verification = true;
            } else if !self.finalized_certificates.contains_key(&outcome.tx_hash) {
                // No tracker, not finalized — buffer for later replay
                self.early_certificates
                    .entry(outcome.tx_hash)
                    .or_insert_with(|| (Vec::new(), current_height))
                    .0
                    .push((shard, outcome.to_shard_proof(ec_hash)));
            }
        }

        if !needs_verification {
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
                "Could not resolve all public keys for execution cert verification"
            );
            return vec![];
        }

        // Delegate signature verification to crypto pool
        vec![Action::VerifyExecutionCertificateSignature {
            certificate: cert,
            public_keys,
        }]
    }

    /// Handle execution certificate signature verification result.
    ///
    /// If valid, extract per-tx outcomes and feed to CertificateTrackers.
    /// Txs without trackers are buffered as early proofs for later replay.
    pub fn on_certificate_verified(
        &mut self,
        topology: &TopologySnapshot,
        certificate: hyperscale_types::ExecutionCertificate,
        valid: bool,
    ) -> Vec<Action> {
        if !valid {
            tracing::warn!(
                shard = certificate.shard_group_id.0,
                block_hash = ?certificate.block_hash,
                wave = %certificate.wave_id,
                "Invalid execution certificate signature"
            );
            return vec![];
        }

        let shard = certificate.shard_group_id;
        let current_height = self.committed_height;
        let ec_hash = certificate.canonical_hash();
        let mut actions = Vec::new();

        // If this is a local shard EC from the wave leader, mark the wave as
        // having an EC so non-leaders stop re-voting in scan_complete_waves,
        // and persist it for fallback serving to remote shards.
        if shard == topology.local_shard() {
            let wave_key = (certificate.block_hash, certificate.wave_id.clone());
            self.waves_with_ec.insert(wave_key);
            let cert_arc = Arc::new(certificate.clone());
            actions.push(Action::PersistExecutionCertificate {
                certificate: cert_arc.clone(),
            });

            // The EC is canonical — overwrite any stale success receipts for
            // transactions the EC declares as aborted.
            actions.extend(self.overwrite_aborted_receipts(&cert_arc));
        }

        // Extract per-tx outcomes — feed to tracker if exists, buffer otherwise
        for outcome in &certificate.tx_outcomes {
            let proof = outcome.to_shard_proof(ec_hash);

            if self.certificate_trackers.contains_key(&outcome.tx_hash) {
                actions.extend(self.handle_certificate_internal(
                    topology,
                    outcome.tx_hash,
                    shard,
                    proof,
                ));
            } else if !self.finalized_certificates.contains_key(&outcome.tx_hash) {
                // Buffer for later replay when block commits
                self.early_certificates
                    .entry(outcome.tx_hash)
                    .or_insert_with(|| (Vec::new(), current_height))
                    .0
                    .push((shard, proof));
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Expected Execution Certificate Tracking
    // ═══════════════════════════════════════════════════════════════════════════

    /// Register expected execution certificates from a remote block header.
    ///
    /// Called when a remote shard's committed block header is received. For each
    /// wave in the header that includes our shard, we register an expected cert.
    /// If the cert doesn't arrive within the timeout, we request it via fallback.
    pub fn on_verified_remote_header(
        &mut self,
        topology: &TopologySnapshot,
        source_shard: ShardGroupId,
        block_hash: Hash,
        block_height: u64,
        waves: &[WaveId],
    ) {
        let local_shard = topology.local_shard();

        for wave in waves {
            if wave.0.contains(&local_shard) {
                let key = (source_shard, block_height, wave.clone());
                // Don't re-register if this cert was already received.
                // Prevents late-arriving duplicate headers from causing
                // spurious fallback requests.
                if self.fulfilled_exec_certs.contains_key(&key) {
                    continue;
                }
                self.expected_exec_certs
                    .entry(key)
                    .or_insert(ExpectedExecCert {
                        block_hash,
                        discovered_at: self.committed_height,
                        last_requested_at: None,
                    });
            }
        }
    }

    /// Check for timed-out expected execution certs and emit fallback requests.
    ///
    /// Called during block commit processing. Returns actions for any certs
    /// that have exceeded the timeout.
    fn check_exec_cert_timeouts(&mut self, topology: &TopologySnapshot) -> Vec<Action> {
        let mut actions = Vec::new();
        let current_height = self.committed_height;
        for ((source_shard, block_height, wave_id), expected) in &mut self.expected_exec_certs {
            let age = current_height.saturating_sub(expected.discovered_at);

            let should_request = match expected.last_requested_at {
                // Never requested — use initial timeout
                None => age >= EXEC_CERT_FALLBACK_TIMEOUT_BLOCKS,
                // Previously requested — use retry interval
                Some(last) => {
                    current_height.saturating_sub(last) >= EXEC_CERT_RETRY_INTERVAL_BLOCKS
                }
            };

            if should_request {
                let is_retry = expected.last_requested_at.is_some();
                expected.last_requested_at = Some(current_height);
                let committee = topology.committee_for_shard(*source_shard);
                let leader =
                    hyperscale_types::wave_leader(&expected.block_hash, wave_id, committee);
                let peers = committee.to_vec();
                tracing::warn!(
                    source_shard = source_shard.0,
                    block_height = block_height,
                    wave = %wave_id,
                    wave_leader = leader.0,
                    age,
                    retry = is_retry,
                    "Execution cert timeout — requesting fallback"
                );
                actions.push(Action::RequestMissingExecutionCert {
                    source_shard: *source_shard,
                    block_height: *block_height,
                    wave_id: wave_id.clone(),
                    wave_leader: leader,
                    peers,
                });
            }
        }
        // Prune old entries that have been requested and are very stale,
        // BUT keep entries whose transactions still have active certificate
        // trackers waiting for the remote EC. Without this, txs whose local
        // EC formed but remote EC never arrived stop retrying and are stuck
        // permanently.
        self.expected_exec_certs.retain(|(_, _, wave_id), e| {
            let age = self.committed_height.saturating_sub(e.discovered_at);
            if age < 100 {
                return true;
            }
            // Check if any tx still needs the remote EC for this wave.
            // A tx needs it if it has either:
            // - An active certificate tracker (waiting for remote proofs to form TC)
            // - A wave assignment to a wave matching this wave_id (EC was sent,
            //   cannot abort — still retrying to get the remote EC)
            let has_waiting_tx = self
                .wave_assignments
                .iter()
                .any(|(_, (_, wid))| wid == wave_id);
            has_waiting_tx
        });

        // Prune fulfilled set using local height when fulfilled (not remote
        // block height, which can differ significantly across shards).
        let fulfilled_cutoff = self.committed_height.saturating_sub(100);
        self.fulfilled_exec_certs
            .retain(|_, &mut fulfilled_at| fulfilled_at > fulfilled_cutoff);

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
    ) -> BlockCommittedOutput {
        let mut actions = Vec::new();
        let mut cross_shard_registrations = Vec::new();

        // ── Provision broadcasting (proposer only) ─────────────────────
        //
        // Provisioning is a block-level proposer duty: the proposer must
        // broadcast state entries for all cross-shard transactions in the
        // committed block, regardless of local execution state.
        let local_shard = topology.local_shard();
        let is_proposer = topology.local_validator_id() == proposer;

        if is_proposer {
            if let Some(cached) = self.take_speculative_provisions(&block_hash) {
                // Speculative provisions already built — send immediately
                tracing::debug!(
                    block_hash = ?block_hash,
                    batch_count = cached.batches.len(),
                    "Speculative provision cache HIT"
                );
                actions.push(Action::SendProvisions {
                    batches: cached.batches,
                    block_timestamp: cached.block_timestamp,
                });
            } else if self.speculative_provision_in_flight.remove(&block_hash) {
                // Speculation in-flight — store full fallback context so we can
                // either send cached results or fall back to FetchAndBroadcastProvisions
                // if speculation returns empty.
                tracing::debug!(
                    block_hash = ?block_hash,
                    "Speculative provisions in-flight — deferring to completion"
                );
                if let Some((requests, shard_recipients)) =
                    Self::build_provision_requests(topology, &transactions, local_shard)
                {
                    self.pending_provision_commits.insert(
                        block_hash,
                        PendingProvisionCommit {
                            block_timestamp,
                            requests,
                            source_shard: local_shard,
                            block_height: BlockHeight(height),
                            shard_recipients,
                        },
                    );
                }
            } else {
                // No speculation — fall back to existing path
                if let Some((requests, shard_recipients)) =
                    Self::build_provision_requests(topology, &transactions, local_shard)
                {
                    actions.push(Action::FetchAndBroadcastProvisions {
                        requests,
                        source_shard: local_shard,
                        block_height: BlockHeight(height),
                        block_timestamp,
                        shard_recipients,
                    });
                }
            }
        }

        // Update committed height before anything else — needed for timeout
        // calculations and pruning even when there are no new transactions.
        if height > self.committed_height {
            self.committed_height = height;
        }

        // Check for timed-out expected execution certs and prune stale entries.
        // Must run every block, not just when there are new transactions.
        actions.extend(self.check_exec_cert_timeouts(topology));

        // Prune ephemeral state (orphaned provisions).
        // Cross-shard resolution state (certificate trackers, finalized certs,
        // pending provisioning, execution cache, early arrivals) is only cleaned
        // up on terminal state — never by block-count timeout.
        self.prune_execution_state();
        self.prune_speculative_provisions();

        if transactions.is_empty() {
            return BlockCommittedOutput {
                actions,
                cross_shard_registrations,
            };
        }

        tracing::debug!(
            height = height,
            tx_count = transactions.len(),
            "Starting execution for new transactions"
        );

        // Set up wave tracking for this block's transactions.
        // Returns any early execution votes that arrived before tracking was ready.
        let early_votes =
            self.setup_execution_tracking(topology, block_hash, height, &transactions);
        for vote in early_votes {
            actions.extend(self.on_execution_vote(topology, vote));
        }

        // Separate single-shard and cross-shard transactions
        let (single_shard, cross_shard): (Vec<_>, Vec<_>) = transactions
            .into_iter()
            .partition(|tx| topology.is_single_shard_transaction(tx));

        // Handle single-shard transactions — set up tracking and execute
        for tx in &single_shard {
            actions.extend(self.start_single_shard_execution(topology, tx.clone()));
        }

        if !single_shard.is_empty() {
            actions.push(Action::ExecuteTransactions {
                block_hash,
                transactions: single_shard,
                state_root: Hash::from_bytes(&[0u8; 32]),
            });
        }

        // Handle cross-shard execution tracking
        let mut cross_shard_requests = Vec::new();
        for tx in cross_shard {
            actions.extend(self.start_cross_shard_execution(
                topology,
                tx,
                height,
                &mut cross_shard_requests,
                &mut cross_shard_registrations,
            ));
        }
        if !cross_shard_requests.is_empty() {
            actions.push(Action::ExecuteCrossShardTransactions {
                requests: cross_shard_requests,
            });
        }

        BlockCommittedOutput {
            actions,
            cross_shard_registrations,
        }
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
        self.certificate_trackers
            .insert(tx_hash, (cert_tracker, self.committed_height));

        // Replay any early proofs that arrived before tracking started.
        if let Some((early_proofs, _arrival_height)) = self.early_certificates.remove(&tx_hash) {
            tracing::debug!(
                tx_hash = ?tx_hash,
                count = early_proofs.len(),
                "Replaying early proofs for single-shard tx"
            );
            for (shard, proof) in early_proofs {
                actions.extend(self.handle_certificate_internal(topology, tx_hash, shard, proof));
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
        cross_shard_requests: &mut Vec<CrossShardExecutionRequest>,
        registrations: &mut Vec<CrossShardRegistration>,
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
            // Register with provision coordinator (via structured output).
            registrations.push(CrossShardRegistration {
                tx_hash,
                required_shards: remote_shards,
                committed_height: BlockHeight(height),
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
                if let Some(req) = self.on_provisioning_complete(topology, tx_hash, provisions) {
                    cross_shard_requests.push(req);
                }
            }
        }

        // Start tracking certificates for finalization
        let cert_tracker = CertificateTracker::new(tx_hash, participating_shards.clone());
        self.certificate_trackers
            .insert(tx_hash, (cert_tracker, self.committed_height));

        // Replay any early proofs that arrived before tracking started.
        if let Some((early_proofs, _arrival_height)) = self.early_certificates.remove(&tx_hash) {
            tracing::debug!(tx_hash = ?tx_hash, count = early_proofs.len(), "Replaying early proofs");
            for (shard, proof) in early_proofs {
                actions.extend(self.handle_certificate_internal(topology, tx_hash, shard, proof));
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
    /// Returns `Some(request)` if execution is ready, `None` if buffered.
    #[instrument(skip(self, provisions), fields(tx_hash = ?tx_hash))]
    pub fn on_provisioning_complete(
        &mut self,
        topology: &TopologySnapshot,
        tx_hash: Hash,
        provisions: Vec<StateProvision>,
    ) -> Option<CrossShardExecutionRequest> {
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
            return None;
        };

        tracing::debug!(
            tx_hash = ?tx_hash,
            shard = local_shard.0,
            provision_count = provisions.len(),
            "Provisioning complete, executing cross-shard transaction"
        );

        Some(CrossShardExecutionRequest {
            tx_hash,
            transaction: tx,
            provisions,
        })
    }

    /// Handle batch provisioning complete for multiple transactions.
    ///
    /// Returns an `ExecuteCrossShardTransactions` action for all transactions
    /// that are ready (block already committed). Transactions whose blocks
    /// haven't committed yet are buffered in `early_provisioning_complete`.
    pub fn on_batch_provisioning_complete(
        &mut self,
        topology: &TopologySnapshot,
        transactions: Vec<hyperscale_core::ProvisionedTransaction>,
    ) -> Vec<Action> {
        let requests: Vec<CrossShardExecutionRequest> = transactions
            .into_iter()
            .filter_map(|pt| self.on_provisioning_complete(topology, pt.tx_hash, pt.provisions))
            .collect();
        if requests.is_empty() {
            vec![]
        } else {
            vec![Action::ExecuteCrossShardTransactions { requests }]
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 5: Finalization
    // ═══════════════════════════════════════════════════════════════════════════

    /// Internal proof handling (assumes tracking is active).
    #[instrument(level = "debug", skip(self, proof), fields(
        tx_hash = %tx_hash,
        cert_shard = cert_shard.0,
    ))]
    fn handle_certificate_internal(
        &mut self,
        topology: &TopologySnapshot,
        tx_hash: Hash,
        cert_shard: ShardGroupId,
        proof: ShardExecutionProof,
    ) -> Vec<Action> {
        let mut actions = Vec::new();

        let local_shard = topology.local_shard();
        let Some((tracker, _)) = self.certificate_trackers.get_mut(&tx_hash) else {
            tracing::debug!(
                tx_hash = ?tx_hash,
                cert_shard = cert_shard.0,
                local_shard = local_shard.0,
                "No certificate tracker for tx, ignoring proof"
            );
            return actions;
        };

        let complete = tracker.add_proof(cert_shard, proof);

        if complete {
            tracing::debug!(
                tx_hash = ?tx_hash,
                shards = tracker.certificate_count(),
                local_shard = local_shard.0,
                "Certificate tracker ready, creating TransactionCertificate"
            );

            // Create transaction certificate
            if let Some(tx_cert) = tracker.create_tx_certificate() {
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

                // Gate on receipt availability: the receipt must have been emitted
                // (via StoreReceiptBundles) so that state root verification can
                // later derive DatabaseUpdates from it. If local execution hasn't
                // finished yet, defer TC creation until the receipt is emitted.
                if !self.receipts_emitted.remove(&tx_hash) {
                    tracing::debug!(
                        tx_hash = %tx_hash,
                        "Certificate tracker complete but receipt not yet emitted — deferring TC creation"
                    );
                    self.deferred_tc_creations.insert(tx_hash);
                    return actions;
                }

                self.finalized_certificates.insert(
                    tx_hash,
                    FinalizedCertEntry {
                        certificate: Arc::new(tx_cert),
                        committed_height: self.committed_height,
                    },
                );

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
        self.finalized_certificates
            .values()
            .map(|entry| Arc::clone(&entry.certificate))
            .collect()
    }

    /// Get a single finalized certificate by transaction hash.
    ///
    /// Returns certificates that have been finalized but not yet committed to a block.
    /// Once committed, certificates are persisted to storage and should be fetched from there.
    pub fn get_finalized_certificate(&self, tx_hash: &Hash) -> Option<Arc<TransactionCertificate>> {
        self.finalized_certificates
            .get(tx_hash)
            .map(|entry| Arc::clone(&entry.certificate))
    }

    /// Remove a finalized certificate (after it's been included in a block).
    ///
    /// Cleans up all transaction tracking state. The certificate itself is already
    /// persisted to storage by this point and can be fetched from there by peers.
    pub fn remove_finalized_certificate(&mut self, tx_hash: &Hash, decision: TransactionDecision) {
        self.finalized_certificates.remove(tx_hash);

        // Clean up receipts_emitted in case TC was never formed for this tx.
        self.receipts_emitted.remove(tx_hash);

        // Clean up all transaction tracking state now that it's finalized.
        // This is the same cleanup done by cleanup_transaction() for aborts/deferrals,
        // but we need to do it here for successful completions too.
        self.pending_provisioning.remove(tx_hash);

        // Remove this TX from the wave's expected set. The TC is canonical —
        // this TX is done and should no longer block the wave from completing.
        //
        // All validators process committed blocks identically, so the reduced
        // expected set is deterministic. The receipt_root will be computed over
        // the remaining TXs only, and all validators will agree.
        //
        // If the TX already has a result in the accumulator (execution completed
        // before the TC committed), remove_expected cleans it up. If not, the
        // TX is simply removed from the expected set, unblocking the wave.
        if let Some(wave_key) = self.wave_assignments.get(tx_hash).cloned() {
            if let Some(accumulator) = self.accumulators.get_mut(&wave_key) {
                let had_result = accumulator.has_result(tx_hash);
                let complete = accumulator.remove_expected(tx_hash);
                if !had_result {
                    tracing::info!(
                        tx_hash = %tx_hash,
                        wave = %wave_key.1,
                        ?decision,
                        complete,
                        "TC committed before local execution — removed from wave"
                    );
                }
            }
        }

        // Wave assignment cleanup — once removed, the accumulator becomes
        // eligible for pruning by prune_execution_state on the next cycle.
        self.wave_assignments.remove(tx_hash);

        self.certificate_trackers.remove(tx_hash);
        self.early_provisioning_complete.remove(tx_hash);
        self.early_certificates.remove(tx_hash);
    }

    /// Prune stale wave state (accumulators, vote trackers, early votes).
    ///
    /// Execution accumulators and vote trackers are keyed by (block_hash, wave_id).
    /// Prune wave state that is no longer needed.
    ///
    /// Only prunes accumulators (and their vote trackers) when they are old
    /// enough AND have no remaining wave_assignments pointing to them. Active
    /// wave_assignments mean the transaction has not yet reached terminal state
    /// (TC committed or abort completed), so the accumulator must stay alive to
    /// allow abort intents and late-arriving votes to resolve the transaction.
    ///
    /// Also prunes early_votes for waves that were never set up.
    fn prune_execution_state(&mut self) {
        // Build set of accumulator keys still referenced by active wave assignments.
        let active_keys: std::collections::HashSet<&(Hash, WaveId)> =
            self.wave_assignments.values().collect();

        // Prune accumulators only when no active wave assignments reference them.
        // Waves must be retained until they resolve (EC formed + TC committed),
        // regardless of age. Time-based pruning would destroy accumulator state
        // needed for abort intents to take effect.
        let before_acc = self.accumulators.len();
        self.accumulators.retain(|key, _| active_keys.contains(key));
        let pruned_acc = before_acc - self.accumulators.len();

        // Prune vote trackers and waves_with_ec — same keys as accumulators.
        // Warn about any vote trackers being pruned with split receipt roots
        // (they never reached quorum, possibly due to non-deterministic execution).
        let before_vt = self.vote_trackers.len();
        self.vote_trackers.retain(|key, tracker| {
            if self.accumulators.contains_key(key) {
                return true;
            }
            // About to prune — log diagnostic if there was a receipt root split
            let root_count = tracker.distinct_receipt_root_count();
            if root_count > 1 {
                let summary = tracker.receipt_root_power_summary();
                tracing::warn!(
                    block_hash = ?key.0,
                    wave = %key.1,
                    receipt_root_split = ?summary,
                    "Pruning vote tracker that never reached quorum — receipt roots were split"
                );
            } else if tracker.total_verified_power() > 0 {
                tracing::warn!(
                    block_hash = ?key.0,
                    wave = %key.1,
                    verified_power = tracker.total_verified_power(),
                    "Pruning vote tracker that never reached quorum — insufficient votes"
                );
            }
            false
        });
        let pruned_vt = before_vt - self.vote_trackers.len();
        self.waves_with_ec
            .retain(|key| self.accumulators.contains_key(key));

        // Prune early execution votes that have been consumed (accumulator exists
        // and would have replayed them) or that are stale (50+ blocks old).
        // We must NOT prune votes for blocks that haven't committed yet — those
        // votes arrived before the accumulator was created and will be replayed
        // when setup_execution_tracking runs during on_block_committed.
        let ev_cutoff = self.committed_height.saturating_sub(50);
        let before_ev = self.early_votes.len();
        self.early_votes.retain(|key, votes| {
            // If the accumulator already exists, the votes were replayed during
            // setup_execution_tracking — safe to prune any leftovers.
            if self.accumulators.contains_key(key) {
                return false;
            }
            // No accumulator yet — keep unless stale.
            votes
                .first()
                .map(|v| v.block_height > ev_cutoff)
                .unwrap_or(false)
        });
        let pruned_ev = before_ev - self.early_votes.len();

        if pruned_acc > 0 || pruned_vt > 0 || pruned_ev > 0 {
            tracing::debug!(
                pruned_acc,
                pruned_vt,
                pruned_ev,
                "Pruned resolved wave state"
            );
        }
    }

    /// Check if a transaction is finalized (TC created from all shard ECs).
    pub fn is_finalized(&self, tx_hash: &Hash) -> bool {
        self.finalized_certificates.contains_key(tx_hash)
    }

    /// Returns the set of all finalized transaction hashes.
    ///
    /// Used by the node orchestrator to pass to BFT for abort intent filtering.
    pub fn finalized_tx_hashes(&self) -> std::collections::HashSet<Hash> {
        self.finalized_certificates.keys().copied().collect()
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

        let cert_tracker_info = if let Some((tracker, _)) = self.certificate_trackers.get(tx_hash) {
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
    ///
    /// IMPORTANT: If a finalized TransactionCertificate exists, we preserve it.
    /// The TC represents cross-shard consensus (all participating shards agreed on
    /// the execution result). A local deferral/abort cannot override that — the TC
    /// must be committed in the next block to supersede the deferral. Removing it
    /// here would cause split-brain: remote shards commit the TC while we discard it.
    ///
    /// Stale TCs (where execution happened locally but was never committed) are
    /// handled by `prune_finalized_certificates()` which runs on every block commit.
    pub fn cleanup_transaction(&mut self, tx_hash: &Hash) {
        // If the transaction is finalized (TC created), we must preserve ALL tracking state.
        // Removing the certificate_tracker, wave_assignment, or finalized_certificate
        // would prevent us from completing the TC when the remote EC arrives — causing
        // split-brain with remote shards that DO form the TC from our EC.
        if self.finalized_certificates.contains_key(tx_hash) {
            tracing::info!(
                tx_hash = %tx_hash,
                finalized = self.finalized_certificates.contains_key(tx_hash),
                "Skipping cleanup for finalized transaction \
                 (must complete TC to avoid split-brain with remote shards)"
            );
            return;
        }

        // Evict receipt tracking — transaction is being retried or abandoned.
        self.receipts_emitted.remove(tx_hash);

        // Phase 1-2: Provisioning cleanup
        // Note: Provision tracking is handled by ProvisionCoordinator
        self.pending_provisioning.remove(tx_hash);

        // Phase 3-4: Vote cleanup

        // Wave voting cleanup
        if let Some(wave_key) = self.wave_assignments.remove(tx_hash) {
            // Don't remove the execution accumulator/tracker — other txs in the wave may still be active.
            // The execution accumulator will be cleaned up when all its txs are cleaned up or the block is abandoned.
            // Just remove this tx's assignment.
            let _ = wave_key;
        }

        // Phase 5: Certificate cleanup
        self.certificate_trackers.remove(tx_hash);

        // Early arrivals cleanup
        self.early_provisioning_complete.remove(tx_hash);
        self.early_certificates.remove(tx_hash);

        tracing::debug!(
            tx_hash = %tx_hash,
            "Cleaned up execution state for deferred/aborted transaction"
        );
    }

    /// Build provision requests and shard recipients for cross-shard transactions.
    ///
    /// Returns `None` if there are no cross-shard transactions needing provisions.
    fn build_provision_requests(
        topology: &TopologySnapshot,
        transactions: &[Arc<RoutableTransaction>],
        local_shard: ShardGroupId,
    ) -> Option<(Vec<ProvisionRequest>, ShardRecipients)> {
        let local_vid = topology.local_validator_id();

        let mut provision_requests = Vec::new();
        for tx in transactions {
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

        if provision_requests.is_empty() {
            return None;
        }

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

        Some((provision_requests, shard_recipients))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Speculative Provision Preparation
    // ═══════════════════════════════════════════════════════════════════════

    /// Trigger speculative provision preparation at proposal time.
    ///
    /// Called after `ProposalBuilt` when the block includes certificates.
    /// Builds the provision request list and emits `SpeculativeProvisionPrep`
    /// to run on the Provisions pool while BFT voting proceeds.
    pub fn trigger_speculative_provisions(
        &mut self,
        topology: &TopologySnapshot,
        block_hash: Hash,
        height: u64,
        block_timestamp: u64,
        transactions: &[Arc<RoutableTransaction>],
        merged_updates: Arc<DatabaseUpdates>,
    ) -> Vec<Action> {
        let local_shard = topology.local_shard();

        let (provision_requests, shard_recipients) =
            match Self::build_provision_requests(topology, transactions, local_shard) {
                Some(result) => result,
                None => return vec![],
            };

        // parent_height = height - 1 (the last committed block)
        let parent_height = self.committed_height;

        self.speculative_provision_in_flight.insert(block_hash);

        tracing::debug!(
            block_hash = ?block_hash,
            height = height,
            request_count = provision_requests.len(),
            parent_height = parent_height,
            "Triggering speculative provision preparation"
        );

        vec![Action::SpeculativeProvisionPrep {
            block_hash,
            requests: provision_requests,
            source_shard: local_shard,
            block_height: BlockHeight(height),
            block_timestamp,
            shard_recipients,
            merged_updates,
            parent_height,
        }]
    }

    /// Handle speculative provision preparation completion.
    ///
    /// Caches the result. If the block has already committed while speculation
    /// was in-flight, immediately emits `SendProvisions`.
    pub fn on_speculative_provisions_complete(
        &mut self,
        block_hash: Hash,
        batches: Vec<(ShardGroupId, ProvisionBatch, Vec<ValidatorId>)>,
        block_timestamp: u64,
    ) -> Vec<Action> {
        self.speculative_provision_in_flight.remove(&block_hash);

        // If batches are empty (e.g., SimStorage fallback), fall back to
        // FetchAndBroadcastProvisions if a commit is pending.
        if batches.is_empty() {
            if let Some(pending) = self.pending_provision_commits.remove(&block_hash) {
                tracing::debug!(
                    block_hash = ?block_hash,
                    "Speculative provision prep returned empty — falling back to FetchAndBroadcastProvisions"
                );
                return vec![Action::FetchAndBroadcastProvisions {
                    requests: pending.requests,
                    source_shard: pending.source_shard,
                    block_height: pending.block_height,
                    block_timestamp: pending.block_timestamp,
                    shard_recipients: pending.shard_recipients,
                }];
            }
            tracing::debug!(
                block_hash = ?block_hash,
                "Speculative provision prep returned empty — no pending commit"
            );
            return vec![];
        }

        // If commit already happened while we were preparing
        if let Some(pending) = self.pending_provision_commits.remove(&block_hash) {
            tracing::debug!(
                block_hash = ?block_hash,
                "Speculative provisions complete — commit was pending, sending now"
            );
            return vec![Action::SendProvisions {
                batches,
                block_timestamp: pending.block_timestamp,
            }];
        }

        // Cache for later use at commit time
        self.speculative_provision_results.insert(
            block_hash,
            CachedProvisions {
                batches,
                block_timestamp,
            },
        );

        vec![]
    }

    /// Take cached speculative provisions for a block, if available.
    fn take_speculative_provisions(&mut self, block_hash: &Hash) -> Option<CachedProvisions> {
        self.speculative_provision_results.remove(block_hash)
    }

    /// Prune stale speculative provision state.
    ///
    /// Entries are normally consumed by `on_block_committed` (cache hit) or
    /// `on_speculative_provisions_complete` (pending commit). This cleans up
    /// orphans from proposals that never committed. Cap-based since we don't
    /// track heights per hash — entries rarely accumulate beyond a handful.
    fn prune_speculative_provisions(&mut self) {
        if self.speculative_provision_results.len() > 10 {
            self.speculative_provision_results.clear();
        }
        if self.speculative_provision_in_flight.len() > 5 {
            self.speculative_provision_in_flight.clear();
        }
        if self.pending_provision_commits.len() > 5 {
            self.pending_provision_commits.clear();
        }
    }

    /// Get execution memory statistics for monitoring collection sizes.
    pub fn memory_stats(&self) -> ExecutionMemoryStats {
        ExecutionMemoryStats {
            receipts_emitted: self.receipts_emitted.len(),
            finalized_certificates: self.finalized_certificates.len(),
            pending_provisioning: self.pending_provisioning.len(),
            accumulators: self.accumulators.len(),
            vote_trackers: self.vote_trackers.len(),
            early_votes: self.early_votes.len(),
            certificate_trackers: self.certificate_trackers.len(),
            expected_exec_certs: self.expected_exec_certs.len(),
            speculative_provision_in_flight: self.speculative_provision_in_flight.len(),
            speculative_provision_results: self.speculative_provision_results.len(),
            pending_provision_commits: self.pending_provision_commits.len(),
        }
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
        for (tx_hash, (tracker, _)) in &self.certificate_trackers {
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
        generate_bls_keypair, Bls12381G1PrivateKey, ValidatorInfo, ValidatorSet,
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
        let actions = state
            .on_block_committed(
                &topology,
                block_hash,
                1,
                1000,
                ValidatorId(0),
                vec![Arc::new(tx.clone())],
            )
            .actions;

        // Should request execution (single-shard path) and set up wave tracking
        assert!(!actions.is_empty());
        // First action should be ExecuteTransactions
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::ExecuteTransactions { .. })));

        // Certificate tracker should be set up for finalization
        assert!(state.certificate_trackers.contains_key(&tx_hash));
    }

    // ========================================================================
    // Crypto Verification Tests - Using real BLS signatures
    // ========================================================================

    #[test]
    fn test_shard_execution_proof_basic() {
        use hyperscale_types::ShardExecutionProof;

        let receipt_hash = Hash::from_bytes(b"commitment");
        let proof = ShardExecutionProof::Executed {
            receipt_hash,
            success: true,
            write_nodes: vec![],
            ec_hash: Hash::ZERO,
        };

        assert!(proof.is_success());
        assert_eq!(proof.receipt_hash_or_zero(), receipt_hash);
        assert!(!proof.is_aborted());
    }

    #[test]
    fn test_batch_verify_execution_votes_different_messages() {
        use hyperscale_test_helpers::TestCommittee;

        let committee = TestCommittee::new(4, 42);
        let shard = ShardGroupId(0);
        let block = Hash::from_bytes(b"block");
        let wave_id = WaveId::zero();

        // Different receipt roots = different messages
        let root1 = Hash::from_bytes(b"root1");
        let root2 = Hash::from_bytes(b"root2");
        let root3 = Hash::from_bytes(b"root3");

        let msg1 = hyperscale_types::exec_vote_message(&block, 1, 1, &wave_id, shard, &root1, 1);
        let msg2 = hyperscale_types::exec_vote_message(&block, 1, 1, &wave_id, shard, &root2, 1);
        let msg3 = hyperscale_types::exec_vote_message(&block, 1, 1, &wave_id, shard, &root3, 1);

        let sig1 = committee.keypair(0).sign_v1(&msg1);
        let sig2 = committee.keypair(1).sign_v1(&msg2);
        let sig3 = committee.keypair(2).sign_v1(&msg3);

        let messages: Vec<&[u8]> = vec![&msg1, &msg2, &msg3];
        let signatures = vec![sig1, sig2, sig3];
        let pubkeys: Vec<_> = (0..3).map(|i| *committee.public_key(i)).collect();

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
        let block = Hash::from_bytes(b"block");
        let wave_id = WaveId::zero();

        let root1 = Hash::from_bytes(b"root1");
        let root2 = Hash::from_bytes(b"root2");

        let msg1 = hyperscale_types::exec_vote_message(&block, 1, 1, &wave_id, shard, &root1, 1);
        let msg2 = hyperscale_types::exec_vote_message(&block, 1, 1, &wave_id, shard, &root2, 1);

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
