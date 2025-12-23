//! ProvisionCoordinator sub-state machine for centralized provision management.
//!
//! This module implements the provision coordination system that tracks all
//! cross-shard provisions, manages signature verification, and emits quorum
//! events for downstream consumers.
//!
//! ## Deferred Verification Optimization
//!
//! Provisions are NOT verified when received. Instead, they are buffered until
//! we have enough for quorum (threshold count). At that point, we send a single
//! `VerifyAndAggregateProvisions` action that:
//! 1. Batch-verifies all signatures (faster than individual verification)
//! 2. Aggregates valid signatures into a CommitmentProof
//! 3. Reports which provisions passed verification
//!
//! This avoids wasting CPU on provisions we'll never use (e.g., if we only
//! receive 2 of 3 needed provisions, we don't verify any).

use hyperscale_core::{Action, Event, SubStateMachine};
use hyperscale_types::{
    BlockHeight, CommitmentProof, Hash, NodeId, PublicKey, ShardGroupId, Signature, SignerBitfield,
    StateEntry, StateProvision, Topology, ValidatorId,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Registration information for a cross-shard transaction.
///
/// Created by ExecutionState when a cross-shard transaction is committed,
/// and used by ProvisionCoordinator to track provision progress.
#[derive(Debug, Clone)]
pub struct TxRegistration {
    /// Shards we need provisions from.
    pub required_shards: BTreeSet<ShardGroupId>,

    /// Quorum threshold per shard (number of provisions needed).
    pub quorum_thresholds: HashMap<ShardGroupId, usize>,

    /// Block height when registered (for potential timeout).
    pub registered_at: BlockHeight,

    /// Nodes needed from each shard (for cycle detection).
    pub nodes_by_shard: HashMap<ShardGroupId, HashSet<NodeId>>,
}

/// Centralized provision coordination.
///
/// Responsibilities:
/// - Receive provisions from network
/// - Buffer provisions until quorum count reached (deferred verification)
/// - Batch verify + aggregate when quorum count reached
/// - Track quorum per (tx, shard)
/// - Notify consumers when provisions are verified/quorum reached
///
/// Note: Backpressure is handled by the mempool module, not here.
/// This module provides `has_any_verified_provisions()` which mempool
/// uses to decide whether to bypass soft limits for cross-shard TXs.
pub struct ProvisionCoordinator {
    // ═══════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════
    /// Local shard ID.
    local_shard: ShardGroupId,

    /// Network topology for validator lookups.
    topology: Arc<dyn Topology>,

    // ═══════════════════════════════════════════════════════════════════
    // Transaction Registration
    // ═══════════════════════════════════════════════════════════════════
    /// Registered cross-shard transactions we're tracking.
    /// Maps tx_hash -> registration info (required shards, thresholds, etc.)
    registered_txs: HashMap<Hash, TxRegistration>,

    // ═══════════════════════════════════════════════════════════════════
    // Provision Lifecycle (Deferred Verification)
    // ═══════════════════════════════════════════════════════════════════
    /// Unverified provisions, buffered until we have enough for quorum.
    /// Key: (tx_hash, source_shard) -> Vec<(StateProvision, PublicKey)>
    /// We store the public key alongside to avoid re-lookup when verifying.
    unverified_provisions: HashMap<(Hash, ShardGroupId), Vec<(StateProvision, PublicKey)>>,

    /// Tracks which validators we've already received provisions from (for dedup).
    /// Key: (tx_hash, validator_id)
    seen_validators: HashSet<(Hash, ValidatorId)>,

    /// Shards that have a pending verification batch in flight.
    /// We don't trigger more verifications until the batch completes.
    pending_verification_batches: HashSet<(Hash, ShardGroupId)>,

    /// Verified provisions, grouped by tx and source shard.
    /// Key: tx_hash -> (source_shard -> Vec<StateProvision>)
    verified_provisions: HashMap<Hash, HashMap<ShardGroupId, Vec<StateProvision>>>,

    // ═══════════════════════════════════════════════════════════════════
    // Quorum Tracking
    // ═══════════════════════════════════════════════════════════════════
    /// Which shards have reached quorum for each tx.
    /// Used to track progress toward full quorum.
    shards_with_quorum: HashMap<Hash, HashSet<ShardGroupId>>,

    /// Transactions that have reached quorum on ALL required shards (ready for execution).
    /// Contains the selected provisions (one per required shard).
    quorum_reached: HashMap<Hash, Vec<StateProvision>>,

    // ═══════════════════════════════════════════════════════════════════
    // Reverse Indexes
    // ═══════════════════════════════════════════════════════════════════
    /// Reverse index: source_shard -> tx_hashes with verified provisions from that shard.
    /// Used by livelock for efficient cycle detection.
    txs_by_source_shard: HashMap<ShardGroupId, HashSet<Hash>>,

    // ═══════════════════════════════════════════════════════════════════
    // Time
    // ═══════════════════════════════════════════════════════════════════
    /// Current time.
    now: Duration,
}

impl std::fmt::Debug for ProvisionCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionCoordinator")
            .field("local_shard", &self.local_shard)
            .field("registered_txs", &self.registered_txs.len())
            .field("unverified_provisions", &self.unverified_provisions.len())
            .field(
                "pending_verification_batches",
                &self.pending_verification_batches.len(),
            )
            .field("verified_provisions", &self.verified_provisions.len())
            .field("quorum_reached", &self.quorum_reached.len())
            .finish()
    }
}

impl ProvisionCoordinator {
    /// Create a new ProvisionCoordinator.
    pub fn new(local_shard: ShardGroupId, topology: Arc<dyn Topology>) -> Self {
        Self {
            local_shard,
            topology,
            registered_txs: HashMap::new(),
            unverified_provisions: HashMap::new(),
            seen_validators: HashSet::new(),
            pending_verification_batches: HashSet::new(),
            verified_provisions: HashMap::new(),
            shards_with_quorum: HashMap::new(),
            quorum_reached: HashMap::new(),
            txs_by_source_shard: HashMap::new(),
            now: Duration::ZERO,
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Provision Lifecycle Methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle provision received from network.
    ///
    /// Buffers the provision until we have enough for quorum. Does NOT verify
    /// until we have threshold count - this avoids wasting CPU on provisions
    /// we'll never use.
    pub fn on_provision_received(&mut self, provision: StateProvision) -> Vec<Action> {
        let tx_hash = provision.transaction_hash;
        let validator_id = provision.validator_id;
        let source_shard = provision.source_shard;

        trace!(
            tx_hash = %tx_hash,
            validator = validator_id.0,
            source_shard = source_shard.0,
            "Provision received"
        );

        // Check if we're tracking this tx (local cross-shard tx we committed)
        let is_registered = self.registered_txs.contains_key(&tx_hash);

        // For unregistered TXs (remote TXs from other shards), we still need to track
        // provisions for livelock cycle detection. We use a default quorum threshold
        // based on the source shard's validator count.
        if !is_registered {
            // Auto-register remote TX with default quorum threshold for its source shard
            let quorum = self.topology.quorum_threshold_for_shard(source_shard) as usize;

            let mut required_shards = BTreeSet::new();
            required_shards.insert(source_shard);

            let mut quorum_thresholds = HashMap::new();
            quorum_thresholds.insert(source_shard, quorum);

            let registration = TxRegistration {
                required_shards,
                quorum_thresholds,
                registered_at: BlockHeight(0), // Unknown for remote TXs
                nodes_by_shard: HashMap::new(),
            };

            trace!(
                tx_hash = %tx_hash,
                source_shard = source_shard.0,
                quorum = quorum,
                "Auto-registering remote transaction for cycle detection"
            );

            self.registered_txs.insert(tx_hash, registration);
        }

        // Deduplicate: already seen this validator for this tx?
        if self.seen_validators.contains(&(tx_hash, validator_id)) {
            trace!(
                tx_hash = %tx_hash,
                validator = validator_id.0,
                "Duplicate provision (already seen)"
            );
            return vec![];
        }

        // Already have verified provision from this validator?
        if self.has_verified_provision_from(tx_hash, validator_id) {
            trace!(
                tx_hash = %tx_hash,
                validator = validator_id.0,
                "Duplicate provision (already verified)"
            );
            return vec![];
        }

        // Already have quorum for this shard? Don't need more provisions.
        if self.shard_has_quorum(tx_hash, source_shard) {
            trace!(
                tx_hash = %tx_hash,
                source_shard = source_shard.0,
                "Ignoring provision (shard already has quorum)"
            );
            return vec![];
        }

        // Get public key for later verification
        let Some(public_key) = self.topology.public_key(validator_id) else {
            warn!(
                tx_hash = %tx_hash,
                validator = validator_id.0,
                "Unknown validator, discarding provision"
            );
            return vec![];
        };

        // Mark as seen to prevent duplicates
        self.seen_validators.insert((tx_hash, validator_id));

        // Buffer the provision (don't verify yet)
        self.unverified_provisions
            .entry((tx_hash, source_shard))
            .or_default()
            .push((provision, public_key));

        // Check if we now have enough to trigger verification
        self.maybe_trigger_verification(tx_hash, source_shard)
    }

    /// Check if we have enough unverified provisions to reach quorum.
    /// If so, trigger batch verification.
    fn maybe_trigger_verification(
        &mut self,
        tx_hash: Hash,
        source_shard: ShardGroupId,
    ) -> Vec<Action> {
        // Already have a verification batch in flight?
        if self
            .pending_verification_batches
            .contains(&(tx_hash, source_shard))
        {
            return vec![];
        }

        // Get threshold for this shard
        let threshold = self
            .registered_txs
            .get(&tx_hash)
            .and_then(|r| r.quorum_thresholds.get(&source_shard))
            .copied()
            .unwrap_or(0);

        if threshold == 0 {
            return vec![];
        }

        // Count how many we already have verified + unverified
        let verified_count = self
            .verified_provisions
            .get(&tx_hash)
            .and_then(|by_shard| by_shard.get(&source_shard))
            .map(|p| p.len())
            .unwrap_or(0);

        let unverified = self.unverified_provisions.get(&(tx_hash, source_shard));

        let unverified_count = unverified.map(|p| p.len()).unwrap_or(0);

        // Do we have enough total to possibly reach quorum?
        let total_count = verified_count + unverified_count;
        if total_count < threshold {
            return vec![];
        }

        // We have enough! Take the unverified provisions and send for batch verification.
        let Some(provisions_with_keys) =
            self.unverified_provisions.remove(&(tx_hash, source_shard))
        else {
            return vec![];
        };

        if provisions_with_keys.is_empty() {
            return vec![];
        }

        // Mark batch as pending
        self.pending_verification_batches
            .insert((tx_hash, source_shard));

        // Get committee info for aggregation
        let committee_size = self.topology.committee_size_for_shard(source_shard);

        // Build the batch verification action
        let provisions: Vec<_> = provisions_with_keys
            .iter()
            .map(|(p, _)| p.clone())
            .collect();
        let public_keys: Vec<_> = provisions_with_keys
            .iter()
            .map(|(_, pk)| pk.clone())
            .collect();

        // Get block height and entries from first provision (all should match)
        let block_height = provisions
            .first()
            .map(|p| p.block_height)
            .unwrap_or(BlockHeight(0));
        let entries: Vec<StateEntry> = provisions
            .first()
            .map(|p| p.entries.as_ref().clone())
            .unwrap_or_default();

        debug!(
            tx_hash = %tx_hash,
            source_shard = source_shard.0,
            provision_count = provisions.len(),
            threshold = threshold,
            "Triggering batch verification (have enough for quorum)"
        );

        vec![Action::VerifyAndAggregateProvisions {
            tx_hash,
            source_shard,
            block_height,
            entries,
            provisions,
            public_keys,
            committee_size,
        }]
    }

    /// Handle batch provision verification and aggregation result.
    ///
    /// Called when the runner finishes verifying a batch of provisions and
    /// aggregating the valid signatures into a CommitmentProof.
    ///
    /// `verified_provisions` contains only the provisions that passed signature
    /// verification. If some failed, they are simply excluded (partial success).
    pub fn on_provisions_verified_and_aggregated(
        &mut self,
        tx_hash: Hash,
        source_shard: ShardGroupId,
        verified_provisions: Vec<StateProvision>,
        commitment_proof: Option<CommitmentProof>,
    ) -> Vec<Action> {
        // Clear the pending batch flag
        self.pending_verification_batches
            .remove(&(tx_hash, source_shard));

        if verified_provisions.is_empty() {
            warn!(
                tx_hash = %tx_hash,
                source_shard = source_shard.0,
                "All provisions in batch failed verification"
            );
            return vec![];
        }

        debug!(
            tx_hash = %tx_hash,
            source_shard = source_shard.0,
            verified_count = verified_provisions.len(),
            "Batch verification complete"
        );

        // Store all verified provisions
        for provision in &verified_provisions {
            self.verified_provisions
                .entry(tx_hash)
                .or_default()
                .entry(source_shard)
                .or_default()
                .push(provision.clone());
        }

        // Update reverse index
        self.txs_by_source_shard
            .entry(source_shard)
            .or_default()
            .insert(tx_hash);

        let mut actions = vec![];

        // Check if quorum reached for this source shard
        if self.check_shard_quorum(tx_hash, source_shard) {
            // Already emitted quorum event for this shard?
            let already_had_quorum = self
                .shards_with_quorum
                .get(&tx_hash)
                .map(|s| s.contains(&source_shard))
                .unwrap_or(false);

            if !already_had_quorum {
                // Track that this shard reached quorum
                self.shards_with_quorum
                    .entry(tx_hash)
                    .or_default()
                    .insert(source_shard);

                // We already have the commitment proof from the batch operation
                if let Some(proof) = commitment_proof {
                    debug!(
                        tx_hash = %tx_hash,
                        source_shard = source_shard.0,
                        signer_count = proof.signer_count(),
                        "Shard quorum reached with aggregated proof"
                    );

                    // Emit quorum event with the pre-aggregated proof
                    actions.push(Action::EnqueueInternal {
                        event: Event::ProvisionQuorumReached {
                            tx_hash,
                            source_shard,
                            commitment_proof: proof,
                        },
                    });
                }

                // Check if ALL required shards have quorum (ready for execution)
                if self.all_shards_have_quorum(tx_hash) {
                    let all_provisions = self.collect_all_quorum_provisions(tx_hash);
                    self.quorum_reached.insert(tx_hash, all_provisions.clone());

                    debug!(
                        tx_hash = %tx_hash,
                        "All shards have quorum - ready for execution"
                    );

                    // Emit event for ExecutionState to trigger cross-shard execution
                    actions.push(Action::EnqueueInternal {
                        event: Event::ProvisioningComplete {
                            tx_hash,
                            provisions: all_provisions,
                        },
                    });
                }
            }
        } else {
            // We verified but still don't have quorum - might need to wait for more
            // provisions or re-trigger verification if more arrived while we were verifying
            let more_actions = self.maybe_trigger_verification(tx_hash, source_shard);
            actions.extend(more_actions);
        }

        actions
    }

    /// Register a cross-shard transaction for tracking.
    ///
    /// Called by ExecutionState when a cross-shard tx is committed.
    pub fn on_tx_registered(&mut self, tx_hash: Hash, registration: TxRegistration) -> Vec<Action> {
        debug!(
            tx_hash = %tx_hash,
            required_shards = ?registration.required_shards,
            "Registering cross-shard transaction"
        );

        self.registered_txs.insert(tx_hash, registration);

        vec![]
    }

    /// Handle cross-shard transaction completion.
    ///
    /// Cleans up all state for the transaction.
    pub fn on_tx_completed(&mut self, tx_hash: &Hash) -> Vec<Action> {
        self.cleanup_tx(tx_hash);
        debug!(tx_hash = %tx_hash, "Cross-shard transaction completed");
        vec![]
    }

    /// Handle cross-shard transaction abort.
    ///
    /// Cleans up all state for the transaction.
    pub fn on_tx_aborted(&mut self, tx_hash: &Hash) -> Vec<Action> {
        self.cleanup_tx(tx_hash);
        debug!(tx_hash = %tx_hash, "Cross-shard transaction aborted");
        vec![]
    }

    /// Handle block committed - cleanup completed/aborted transactions.
    pub fn on_block_committed(&mut self, block: &hyperscale_types::Block) -> Vec<Action> {
        // Clean up completed transactions (certificates committed)
        for cert in &block.committed_certificates {
            self.cleanup_tx(&cert.transaction_hash);
        }

        // Clean up aborted transactions
        for abort in &block.aborted {
            self.cleanup_tx(&abort.tx_hash);
        }

        // Clean up deferred transactions
        for deferral in &block.deferred {
            self.cleanup_tx(&deferral.tx_hash);
        }

        vec![]
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Query Methods (for other modules)
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if a transaction has any verified provisions.
    ///
    /// Used by backpressure: if true, another shard has committed,
    /// so we must cooperate regardless of limits.
    ///
    /// This must be consistent with `build_commitment_proof` - if this returns true,
    /// then `build_commitment_proof` must return Some. We check that at least one
    /// shard has a non-empty provisions Vec.
    pub fn has_any_verified_provisions(&self, tx_hash: &Hash) -> bool {
        self.verified_provisions
            .get(tx_hash)
            .map(|by_shard| by_shard.values().any(|provisions| !provisions.is_empty()))
            .unwrap_or(false)
    }

    /// Check if quorum has been reached for a transaction (all required shards).
    ///
    /// Used by execution to know when to proceed.
    pub fn has_quorum(&self, tx_hash: &Hash) -> bool {
        self.quorum_reached.contains_key(tx_hash)
    }

    /// Get the provisions for a transaction that has reached quorum.
    ///
    /// Returns None if quorum not yet reached.
    pub fn get_quorum_provisions(&self, tx_hash: &Hash) -> Option<&Vec<StateProvision>> {
        self.quorum_reached.get(tx_hash)
    }

    /// Get all tx_hashes with verified provisions from a specific shard.
    ///
    /// Used by livelock for cycle detection.
    pub fn txs_with_provisions_from(&self, shard: ShardGroupId) -> Option<&HashSet<Hash>> {
        self.txs_by_source_shard.get(&shard)
    }

    /// Get the nodes contained in verified provisions for a tx from a specific shard.
    ///
    /// Used by livelock to check for actual node-level overlap.
    pub fn provision_nodes(&self, tx_hash: Hash, shard: ShardGroupId) -> HashSet<NodeId> {
        self.verified_provisions
            .get(&tx_hash)
            .and_then(|by_shard| by_shard.get(&shard))
            .map(|provisions| {
                provisions
                    .iter()
                    .flat_map(|p| p.entries.iter().filter_map(|e| e.node_id()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if a transaction is registered.
    pub fn is_registered(&self, tx_hash: &Hash) -> bool {
        self.registered_txs.contains_key(tx_hash)
    }

    /// Get the registration for a transaction.
    pub fn get_registration(&self, tx_hash: &Hash) -> Option<&TxRegistration> {
        self.registered_txs.get(tx_hash)
    }

    /// Build a CommitmentProof for a transaction that has verified provisions.
    ///
    /// Returns `None` if:
    /// - No verified provisions exist for this transaction
    /// - No provisions from the first source shard
    ///
    /// The proof is built from the first source shard that has provisions.
    /// This is sufficient for backpressure purposes - it proves another shard committed.
    ///
    /// Note: Currently uses a placeholder signature since we need BLS aggregation.
    /// The signature verification is deferred to Phase 5c BFT validation.
    pub fn build_commitment_proof(&self, tx_hash: &Hash) -> Option<CommitmentProof> {
        let by_shard = self.verified_provisions.get(tx_hash)?;

        // Find a shard that has non-empty provisions.
        // We can't just use .next() because HashMap iteration order is arbitrary,
        // and some shards may have empty provision vectors. This must be consistent
        // with has_any_verified_provisions() which checks if ANY shard has provisions.
        let (source_shard, provisions) = by_shard
            .iter()
            .find(|(_, provisions)| !provisions.is_empty())?;

        // Get block height and entries from the first provision
        // All provisions for the same (tx, shard) should have same entries
        let first_provision = &provisions[0];
        let block_height = first_provision.block_height;
        let entries = Arc::clone(&first_provision.entries);

        // Build signer bitfield from validator IDs
        let num_validators = self.topology.global_validator_set().len();
        let mut signers = SignerBitfield::new(num_validators);

        for provision in provisions {
            // ValidatorId(0) -> index 0, etc.
            let validator_index = provision.validator_id.0 as usize;
            if validator_index < num_validators {
                signers.set(validator_index);
            }
        }

        // TODO: Implement actual BLS signature aggregation
        // For now, we use a placeholder signature. The BFT validation
        // in Phase 5d will verify individual provision signatures.
        let aggregated_signature = Signature::zero();

        Some(CommitmentProof::new(
            *tx_hash,
            *source_shard,
            signers,
            aggregated_signature,
            block_height,
            (*entries).clone(),
        ))
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internal Helper Methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if we already have a verified provision from this validator.
    fn has_verified_provision_from(&self, tx_hash: Hash, validator_id: ValidatorId) -> bool {
        self.verified_provisions
            .get(&tx_hash)
            .map(|by_shard| {
                by_shard
                    .values()
                    .any(|provisions| provisions.iter().any(|p| p.validator_id == validator_id))
            })
            .unwrap_or(false)
    }

    /// Check if quorum threshold is reached for a specific shard.
    fn check_shard_quorum(&self, tx_hash: Hash, shard: ShardGroupId) -> bool {
        let Some(registration) = self.registered_txs.get(&tx_hash) else {
            return false;
        };

        let Some(&threshold) = registration.quorum_thresholds.get(&shard) else {
            return false;
        };

        let provision_count = self
            .verified_provisions
            .get(&tx_hash)
            .and_then(|by_shard| by_shard.get(&shard))
            .map(|p| p.len())
            .unwrap_or(0);

        provision_count >= threshold
    }

    /// Check if we already have quorum for a shard (already emitted quorum event).
    fn shard_has_quorum(&self, tx_hash: Hash, shard: ShardGroupId) -> bool {
        self.shards_with_quorum
            .get(&tx_hash)
            .map(|s| s.contains(&shard))
            .unwrap_or(false)
    }

    /// Check if all required shards have reached quorum.
    fn all_shards_have_quorum(&self, tx_hash: Hash) -> bool {
        let Some(registration) = self.registered_txs.get(&tx_hash) else {
            return false;
        };

        let Some(shards_with_quorum) = self.shards_with_quorum.get(&tx_hash) else {
            return false;
        };

        registration
            .required_shards
            .iter()
            .all(|shard| shards_with_quorum.contains(shard))
    }

    /// Collect one provision per required shard (for full quorum).
    fn collect_all_quorum_provisions(&self, tx_hash: Hash) -> Vec<StateProvision> {
        let Some(registration) = self.registered_txs.get(&tx_hash) else {
            return vec![];
        };

        registration
            .required_shards
            .iter()
            .filter_map(|shard| {
                self.verified_provisions
                    .get(&tx_hash)
                    .and_then(|by_shard| by_shard.get(shard))
                    .and_then(|provisions| provisions.first().cloned())
            })
            .collect()
    }

    /// Clean up all state for a transaction.
    fn cleanup_tx(&mut self, tx_hash: &Hash) {
        // Remove registration
        self.registered_txs.remove(tx_hash);

        // Remove seen validators for this tx
        self.seen_validators.retain(|(h, _)| h != tx_hash);

        // Remove unverified provisions for all shards
        self.unverified_provisions.retain(|(h, _), _| h != tx_hash);

        // Remove pending verification batches
        self.pending_verification_batches
            .retain(|(h, _)| h != tx_hash);

        // Remove verified provisions and update reverse index
        if let Some(by_shard) = self.verified_provisions.remove(tx_hash) {
            for shard in by_shard.keys() {
                if let Some(txs) = self.txs_by_source_shard.get_mut(shard) {
                    txs.remove(tx_hash);
                }
            }
        }

        // Remove quorum tracking
        self.shards_with_quorum.remove(tx_hash);
        self.quorum_reached.remove(tx_hash);
    }
}

impl SubStateMachine for ProvisionCoordinator {
    fn try_handle(&mut self, event: &Event) -> Option<Vec<Action>> {
        match event {
            // ═══════════════════════════════════════════════════════════
            // Provision Lifecycle
            // ═══════════════════════════════════════════════════════════
            Event::StateProvisionReceived { provision } => {
                Some(self.on_provision_received(provision.clone()))
            }

            // Callback from batch verification + aggregation
            Event::ProvisionsVerifiedAndAggregated {
                tx_hash,
                source_shard,
                verified_provisions,
                commitment_proof,
            } => Some(self.on_provisions_verified_and_aggregated(
                *tx_hash,
                *source_shard,
                verified_provisions.clone(),
                commitment_proof.clone(),
            )),

            // ═══════════════════════════════════════════════════════════
            // Transaction Registration (from ExecutionState)
            // ═══════════════════════════════════════════════════════════
            Event::CrossShardTxRegistered {
                tx_hash,
                required_shards,
                quorum_thresholds,
                committed_height,
            } => {
                let registration = TxRegistration {
                    required_shards: required_shards.clone(),
                    quorum_thresholds: quorum_thresholds.clone(),
                    registered_at: *committed_height,
                    nodes_by_shard: HashMap::new(), // Populated later if needed
                };
                Some(self.on_tx_registered(*tx_hash, registration))
            }

            // ═══════════════════════════════════════════════════════════
            // Transaction Completion/Abort (cleanup)
            // ═══════════════════════════════════════════════════════════
            Event::CrossShardTxCompleted { tx_hash } => Some(self.on_tx_completed(tx_hash)),

            Event::CrossShardTxAborted { tx_hash } => Some(self.on_tx_aborted(tx_hash)),

            // ═══════════════════════════════════════════════════════════
            // Block Lifecycle (cleanup)
            // ═══════════════════════════════════════════════════════════
            Event::BlockCommitted { block, .. } => Some(self.on_block_committed(block)),

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
    use hyperscale_types::{KeyPair, Signature, StaticTopology, ValidatorInfo, ValidatorSet};

    fn make_test_topology(local_shard: ShardGroupId) -> Arc<dyn Topology> {
        // Create a simple topology with 3 validators per shard (2 shards)
        let validators: Vec<_> = (0..6)
            .map(|i| ValidatorInfo {
                validator_id: ValidatorId(i),
                public_key: KeyPair::generate_ed25519().public_key(),
                voting_power: 1,
            })
            .collect();

        Arc::new(StaticTopology::with_local_shard(
            ValidatorId(local_shard.0 * 3), // First validator in shard
            local_shard,
            2,
            ValidatorSet::new(validators),
        ))
    }

    fn make_provision(
        tx_hash: Hash,
        source_shard: ShardGroupId,
        validator_id: ValidatorId,
    ) -> StateProvision {
        StateProvision {
            transaction_hash: tx_hash,
            target_shard: ShardGroupId(0),
            source_shard,
            block_height: BlockHeight(1),
            entries: Arc::new(vec![]),
            validator_id,
            signature: Signature::zero(),
        }
    }

    fn make_provision_with_nodes(
        tx_hash: Hash,
        source_shard: ShardGroupId,
        validator_id: ValidatorId,
        node_ids: Vec<NodeId>,
    ) -> StateProvision {
        let entries: Vec<_> = node_ids
            .into_iter()
            .map(|node_id| StateEntry::test_entry(node_id, 0, vec![], None))
            .collect();
        StateProvision {
            transaction_hash: tx_hash,
            target_shard: ShardGroupId(0),
            source_shard,
            block_height: BlockHeight(1),
            entries: Arc::new(entries),
            validator_id,
            signature: Signature::zero(),
        }
    }

    fn make_registration(required_shards: Vec<ShardGroupId>, threshold: usize) -> TxRegistration {
        let quorum_thresholds = required_shards.iter().map(|s| (*s, threshold)).collect();
        TxRegistration {
            required_shards: required_shards.into_iter().collect(),
            quorum_thresholds,
            registered_at: BlockHeight(1),
            nodes_by_shard: HashMap::new(),
        }
    }

    fn make_test_node_id(id: u8) -> NodeId {
        let mut bytes = [0u8; 30];
        bytes[0] = id;
        NodeId::from_bytes(&bytes)
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Core Lifecycle Tests (Deferred Verification Model)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_provision_buffered_until_quorum_count() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        // First provision - should be buffered, no verification triggered
        let provision1 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        let actions1 = coordinator.on_provision_received(provision1);
        assert!(
            actions1.is_empty(),
            "First provision should be buffered, not verified"
        );

        // Second provision - now have quorum count, should trigger batch verification
        let provision2 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(4));
        let actions2 = coordinator.on_provision_received(provision2);
        assert_eq!(
            actions2.len(),
            1,
            "Should trigger batch verification at quorum count"
        );
        assert!(matches!(
            actions2[0],
            Action::VerifyAndAggregateProvisions { .. }
        ));
    }

    #[test]
    fn test_provisions_verified_and_aggregated_stores_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        let provision1 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        let provision2 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(4));

        // Buffer both provisions
        coordinator.on_provision_received(provision1.clone());
        coordinator.on_provision_received(provision2.clone());

        // Simulate batch verification callback with both valid
        coordinator.on_provisions_verified_and_aggregated(
            tx_hash,
            ShardGroupId(1),
            vec![provision1, provision2],
            None, // No proof for this test
        );

        // Should be stored
        assert!(coordinator.has_any_verified_provisions(&tx_hash));

        // Reverse index should be updated
        let txs = coordinator.txs_with_provisions_from(ShardGroupId(1));
        assert!(txs.is_some());
        assert!(txs.unwrap().contains(&tx_hash));
    }

    #[test]
    fn test_batch_verification_partial_failure() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        let provision1 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        let provision2 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(4));

        // Buffer both provisions
        coordinator.on_provision_received(provision1.clone());
        coordinator.on_provision_received(provision2);

        // Simulate batch verification callback with only one valid (partial failure)
        coordinator.on_provisions_verified_and_aggregated(
            tx_hash,
            ShardGroupId(1),
            vec![provision1], // Only provision1 passed
            None,
        );

        // Only valid provision should be stored
        assert!(coordinator.has_any_verified_provisions(&tx_hash));
        // But not at quorum yet (need 2, only have 1 valid)
        assert!(!coordinator.has_quorum(&tx_hash));
    }

    #[test]
    fn test_batch_verification_all_fail() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        let provision1 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        let provision2 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(4));

        // Buffer both provisions
        coordinator.on_provision_received(provision1);
        coordinator.on_provision_received(provision2);

        // Simulate batch verification callback with all failed
        coordinator.on_provisions_verified_and_aggregated(
            tx_hash,
            ShardGroupId(1),
            vec![], // None passed
            None,
        );

        // Should NOT have any verified provisions
        assert!(!coordinator.has_any_verified_provisions(&tx_hash));
    }

    #[test]
    fn test_remote_tx_auto_registered() {
        // Remote TXs (provisions for unregistered TXs) are now auto-registered
        // for livelock cycle detection.
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let provision = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));

        // Receive provision for unregistered (remote) TX
        // Auto-registration uses topology quorum threshold (2 for our test topology)
        coordinator.on_provision_received(provision);

        // TX should now be registered
        assert!(coordinator.is_registered(&tx_hash));
    }

    #[test]
    fn test_explicit_registration_overrides_auto() {
        // If a TX is explicitly registered after auto-registration,
        // the explicit registration takes precedence.
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let provision = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));

        // First, receive provision (triggers auto-registration)
        coordinator.on_provision_received(provision);
        assert!(coordinator.is_registered(&tx_hash));

        // Auto-registration only requires shard 1 (from the provision)
        let auto_reg = coordinator.get_registration(&tx_hash).unwrap();
        assert!(auto_reg.required_shards.contains(&ShardGroupId(1)));

        // Now explicitly register with different requirements
        let registration = make_registration(vec![ShardGroupId(1), ShardGroupId(2)], 2);
        let actions = coordinator.on_tx_registered(tx_hash, registration);

        // No verification actions from registration
        assert!(actions.is_empty());

        // Explicit registration should override - now requires both shards
        let reg = coordinator.get_registration(&tx_hash).unwrap();
        assert!(reg.required_shards.contains(&ShardGroupId(1)));
        assert!(reg.required_shards.contains(&ShardGroupId(2)));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Quorum Tracking Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_shard_quorum_reached() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        // Require 2 provisions from shard 1
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        // First provision - buffered
        let p1 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        coordinator.on_provision_received(p1.clone());
        assert!(!coordinator.has_quorum(&tx_hash));

        // Second provision - triggers verification
        let p2 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(4));
        coordinator.on_provision_received(p2.clone());

        // Simulate successful batch verification with commitment proof
        let proof = CommitmentProof::new(
            tx_hash,
            ShardGroupId(1),
            SignerBitfield::new(4),
            Signature::zero(),
            BlockHeight(1),
            vec![],
        );
        coordinator.on_provisions_verified_and_aggregated(
            tx_hash,
            ShardGroupId(1),
            vec![p1, p2],
            Some(proof),
        );

        // Now at quorum (single shard requirement)
        assert!(coordinator.has_quorum(&tx_hash));
    }

    #[test]
    fn test_all_shards_quorum_marks_ready() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        // Require 1 provision from shard 1
        let registration = make_registration(vec![ShardGroupId(1)], 1);
        coordinator.on_tx_registered(tx_hash, registration);

        let p = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        coordinator.on_provision_received(p.clone());

        // Simulate batch verification
        let proof = CommitmentProof::new(
            tx_hash,
            ShardGroupId(1),
            SignerBitfield::new(4),
            Signature::zero(),
            BlockHeight(1),
            vec![],
        );
        coordinator.on_provisions_verified_and_aggregated(
            tx_hash,
            ShardGroupId(1),
            vec![p],
            Some(proof),
        );

        // Should be ready
        assert!(coordinator.has_quorum(&tx_hash));
        assert!(coordinator.get_quorum_provisions(&tx_hash).is_some());
    }

    #[test]
    fn test_duplicate_provision_ignored() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        let provision = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));

        // First receive - buffered
        let actions1 = coordinator.on_provision_received(provision.clone());
        assert!(actions1.is_empty()); // Still buffered

        // Duplicate (same validator) - should be ignored
        let actions2 = coordinator.on_provision_received(provision.clone());
        assert!(actions2.is_empty());

        // Try a different validator - this should work
        let provision2 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(4));
        let actions3 = coordinator.on_provision_received(provision2);
        // Now we have 2 provisions (threshold), should trigger verification
        assert_eq!(actions3.len(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Query Method Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_has_any_verified_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 1);
        coordinator.on_tx_registered(tx_hash, registration);

        assert!(!coordinator.has_any_verified_provisions(&tx_hash));

        let provision = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        coordinator.on_provision_received(provision.clone());

        // Simulate batch verification
        coordinator.on_provisions_verified_and_aggregated(
            tx_hash,
            ShardGroupId(1),
            vec![provision],
            None,
        );

        assert!(coordinator.has_any_verified_provisions(&tx_hash));
    }

    #[test]
    fn test_provision_nodes_extracts_node_ids() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 1);
        coordinator.on_tx_registered(tx_hash, registration);

        let node1 = make_test_node_id(1);
        let node2 = make_test_node_id(2);
        let provision =
            make_provision_with_nodes(tx_hash, ShardGroupId(1), ValidatorId(3), vec![node1, node2]);

        coordinator.on_provision_received(provision.clone());

        // Simulate batch verification
        coordinator.on_provisions_verified_and_aggregated(
            tx_hash,
            ShardGroupId(1),
            vec![provision],
            None,
        );

        let nodes = coordinator.provision_nodes(tx_hash, ShardGroupId(1));
        assert!(nodes.contains(&node1));
        assert!(nodes.contains(&node2));
    }

    #[test]
    fn test_build_commitment_proof_returns_none_without_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        assert!(coordinator.build_commitment_proof(&tx_hash).is_none());
    }

    #[test]
    fn test_build_commitment_proof_success() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        // Add two verified provisions via batch verification
        let provision1 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        let provision2 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(4));

        coordinator.on_provision_received(provision1.clone());
        coordinator.on_provision_received(provision2.clone());

        // Simulate batch verification
        coordinator.on_provisions_verified_and_aggregated(
            tx_hash,
            ShardGroupId(1),
            vec![provision1, provision2],
            None,
        );

        // Build proof
        let proof = coordinator.build_commitment_proof(&tx_hash);
        assert!(proof.is_some());

        let proof = proof.unwrap();
        assert_eq!(proof.tx_hash, tx_hash);
        assert_eq!(proof.source_shard, ShardGroupId(1));
        assert_eq!(proof.signer_count(), 2);
        assert!(proof.signer_indices().contains(&3));
        assert!(proof.signer_indices().contains(&4));
    }

    #[test]
    fn test_build_commitment_proof_includes_entries() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 1);
        coordinator.on_tx_registered(tx_hash, registration);

        let node1 = make_test_node_id(1);
        let node2 = make_test_node_id(2);
        let provision =
            make_provision_with_nodes(tx_hash, ShardGroupId(1), ValidatorId(3), vec![node1, node2]);

        coordinator.on_provision_received(provision.clone());

        // Simulate batch verification
        coordinator.on_provisions_verified_and_aggregated(
            tx_hash,
            ShardGroupId(1),
            vec![provision],
            None,
        );

        let proof = coordinator.build_commitment_proof(&tx_hash).unwrap();

        // Verify entries are included
        assert_eq!(proof.entries.len(), 2);
        let proof_nodes = proof.nodes();
        assert!(proof_nodes.contains(&node1));
        assert!(proof_nodes.contains(&node2));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tx_completed_cleans_up_state() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 1);
        coordinator.on_tx_registered(tx_hash, registration);

        let provision = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        coordinator.on_provision_received(provision.clone());

        // Simulate batch verification
        coordinator.on_provisions_verified_and_aggregated(
            tx_hash,
            ShardGroupId(1),
            vec![provision],
            None,
        );

        // Verify state exists
        assert!(coordinator.is_registered(&tx_hash));
        assert!(coordinator.has_any_verified_provisions(&tx_hash));

        // Complete transaction
        coordinator.on_tx_completed(&tx_hash);

        // All state should be cleaned up
        assert!(!coordinator.is_registered(&tx_hash));
        assert!(!coordinator.has_any_verified_provisions(&tx_hash));
        assert!(!coordinator.has_quorum(&tx_hash));
    }

    #[test]
    fn test_tx_aborted_cleans_up_state() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 1);
        coordinator.on_tx_registered(tx_hash, registration);

        // Abort before any provisions
        coordinator.on_tx_aborted(&tx_hash);

        assert!(!coordinator.is_registered(&tx_hash));
    }
}
