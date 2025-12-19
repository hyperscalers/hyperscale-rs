//! ProvisionCoordinator sub-state machine for centralized provision management.
//!
//! This module implements the provision coordination system that tracks all
//! cross-shard provisions, manages signature verification, and emits quorum
//! events for downstream consumers.

use crate::ProvisionConfig;
use hyperscale_core::{Action, Event, SubStateMachine};
use hyperscale_types::{
    BlockHeight, CommitmentProof, Hash, NodeId, ShardGroupId, Signature, SignerBitfield,
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
/// - Manage signature verification lifecycle
/// - Track quorum per (tx, shard)
/// - Enforce backpressure limits
/// - Notify consumers when provisions are verified/quorum reached
pub struct ProvisionCoordinator {
    // ═══════════════════════════════════════════════════════════════════
    // Configuration
    // ═══════════════════════════════════════════════════════════════════
    /// Local shard ID.
    local_shard: ShardGroupId,

    /// Network topology for validator lookups.
    topology: Arc<dyn Topology>,

    /// Backpressure configuration.
    config: ProvisionConfig,

    // ═══════════════════════════════════════════════════════════════════
    // Transaction Registration
    // ═══════════════════════════════════════════════════════════════════
    /// Registered cross-shard transactions we're tracking.
    /// Maps tx_hash -> registration info (required shards, thresholds, etc.)
    registered_txs: HashMap<Hash, TxRegistration>,

    // ═══════════════════════════════════════════════════════════════════
    // Provision Lifecycle
    // ═══════════════════════════════════════════════════════════════════
    /// Provisions pending signature verification.
    /// Key: (tx_hash, validator_id)
    pending_verifications: HashMap<(Hash, ValidatorId), StateProvision>,

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

    /// Reverse index for cleanup: tx_hash -> validators with pending verifications.
    pending_verifications_by_tx: HashMap<Hash, HashSet<ValidatorId>>,

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
            .field("pending_verifications", &self.pending_verifications.len())
            .field("verified_provisions", &self.verified_provisions.len())
            .field("quorum_reached", &self.quorum_reached.len())
            .finish()
    }
}

impl ProvisionCoordinator {
    /// Create a new ProvisionCoordinator.
    pub fn new(local_shard: ShardGroupId, topology: Arc<dyn Topology>) -> Self {
        Self::with_config(local_shard, topology, ProvisionConfig::default())
    }

    /// Create a new ProvisionCoordinator with custom configuration.
    pub fn with_config(
        local_shard: ShardGroupId,
        topology: Arc<dyn Topology>,
        config: ProvisionConfig,
    ) -> Self {
        Self {
            local_shard,
            topology,
            config,
            registered_txs: HashMap::new(),
            pending_verifications: HashMap::new(),
            verified_provisions: HashMap::new(),
            shards_with_quorum: HashMap::new(),
            quorum_reached: HashMap::new(),
            txs_by_source_shard: HashMap::new(),
            pending_verifications_by_tx: HashMap::new(),
            now: Duration::ZERO,
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Provision Lifecycle Methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle provision received from network.
    ///
    /// Queues for signature verification. Does NOT process until verified.
    pub fn on_provision_received(&mut self, provision: StateProvision) -> Vec<Action> {
        let tx_hash = provision.transaction_hash;
        let validator_id = provision.validator_id;

        trace!(
            tx_hash = %tx_hash,
            validator = validator_id.0,
            source_shard = provision.source_shard.0,
            "Provision received"
        );

        // Check if we're tracking this tx (local cross-shard tx we committed)
        let is_registered = self.registered_txs.contains_key(&tx_hash);

        // For unregistered TXs (remote TXs from other shards), we still need to track
        // provisions for livelock cycle detection. We use a default quorum threshold
        // based on the source shard's validator count.
        if !is_registered {
            // Auto-register remote TX with default quorum threshold for its source shard
            let source_shard = provision.source_shard;
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

        // Deduplicate: already pending verification?
        if self
            .pending_verifications
            .contains_key(&(tx_hash, validator_id))
        {
            trace!(
                tx_hash = %tx_hash,
                validator = validator_id.0,
                "Duplicate provision (pending verification)"
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

        // Get public key for verification
        let Some(public_key) = self.topology.public_key(validator_id) else {
            warn!(
                tx_hash = %tx_hash,
                validator = validator_id.0,
                "Unknown validator, discarding provision"
            );
            return vec![];
        };

        // Queue for verification
        self.pending_verifications
            .insert((tx_hash, validator_id), provision.clone());
        self.pending_verifications_by_tx
            .entry(tx_hash)
            .or_default()
            .insert(validator_id);

        vec![Action::VerifyProvisionSignature {
            provision,
            public_key,
        }]
    }

    /// Handle provision signature verification result.
    ///
    /// Only after this do we consider the provision "real".
    pub fn on_provision_verified(&mut self, provision: StateProvision, valid: bool) -> Vec<Action> {
        let tx_hash = provision.transaction_hash;
        let validator_id = provision.validator_id;
        let source_shard = provision.source_shard;

        // Remove from pending
        self.pending_verifications.remove(&(tx_hash, validator_id));
        if let Some(pending) = self.pending_verifications_by_tx.get_mut(&tx_hash) {
            pending.remove(&validator_id);
        }

        if !valid {
            warn!(
                tx_hash = %tx_hash,
                validator = validator_id.0,
                "Invalid provision signature"
            );
            return vec![];
        }

        debug!(
            tx_hash = %tx_hash,
            validator = validator_id.0,
            source_shard = source_shard.0,
            "Provision verified"
        );

        // Store verified provision
        self.verified_provisions
            .entry(tx_hash)
            .or_default()
            .entry(source_shard)
            .or_default()
            .push(provision.clone());

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

                // Collect the provisions that form the quorum
                let quorum_provisions = self.collect_shard_quorum_provisions(tx_hash, source_shard);

                // Build aggregation request - runner will do the BLS aggregation
                let aggregation_action =
                    self.build_aggregation_action(tx_hash, source_shard, &quorum_provisions);

                debug!(
                    tx_hash = %tx_hash,
                    source_shard = source_shard.0,
                    provision_count = quorum_provisions.len(),
                    "Shard quorum reached - requesting signature aggregation"
                );

                // Emit action for runner to aggregate signatures
                actions.push(aggregation_action);

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
                    .flat_map(|p| p.entries.iter().map(|e| e.node_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get current count of cross-shard transactions in flight.
    ///
    /// Used by backpressure to decide whether to accept new cross-shard txs.
    pub fn cross_shard_pending_count(&self) -> usize {
        self.registered_txs.len()
    }

    /// Check if we're at the backpressure limit.
    pub fn at_backpressure_limit(&self) -> bool {
        self.config.backpressure_enabled
            && self.cross_shard_pending_count() >= self.config.max_cross_shard_pending
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

        // Get the first shard that has provisions
        let (source_shard, provisions) = by_shard.iter().next()?;

        if provisions.is_empty() {
            return None;
        }

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

    /// Collect provisions that form quorum for a specific shard.
    ///
    /// Returns up to threshold provisions, selecting deterministically.
    fn collect_shard_quorum_provisions(
        &self,
        tx_hash: Hash,
        shard: ShardGroupId,
    ) -> Vec<StateProvision> {
        let threshold = self
            .registered_txs
            .get(&tx_hash)
            .and_then(|r| r.quorum_thresholds.get(&shard))
            .copied()
            .unwrap_or(0);

        self.verified_provisions
            .get(&tx_hash)
            .and_then(|by_shard| by_shard.get(&shard))
            .map(|provisions| provisions.iter().take(threshold).cloned().collect())
            .unwrap_or_default()
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

    /// Handle the callback when commitment proof aggregation completes.
    ///
    /// Emits `ProvisionQuorumReached` for downstream consumers (livelock, execution).
    fn on_commitment_proof_aggregated(
        &mut self,
        tx_hash: Hash,
        source_shard: ShardGroupId,
        commitment_proof: CommitmentProof,
    ) -> Vec<Action> {
        debug!(
            tx_hash = %tx_hash,
            source_shard = source_shard.0,
            signer_count = commitment_proof.signer_count(),
            "Commitment proof aggregated"
        );

        // Emit event for downstream consumers (livelock, execution)
        vec![Action::EnqueueInternal {
            event: Event::ProvisionQuorumReached {
                tx_hash,
                source_shard,
                commitment_proof,
            },
        }]
    }

    /// Build an aggregation action for the runner to perform BLS signature aggregation.
    ///
    /// The runner will aggregate the signatures and return the CommitmentProof
    /// via the CommitmentProofAggregated event.
    fn build_aggregation_action(
        &self,
        tx_hash: Hash,
        source_shard: ShardGroupId,
        provisions: &[StateProvision],
    ) -> Action {
        // Get committee size for the source shard to build proper SignerBitfield
        let committee_size = self.topology.committee_size_for_shard(source_shard);

        // Collect signatures and signer indices
        let mut signatures = Vec::with_capacity(provisions.len());
        let mut signer_indices = Vec::with_capacity(provisions.len());

        for provision in provisions {
            // Get validator's index in the source shard committee
            if let Some(idx) = self
                .topology
                .committee_index_for_shard(source_shard, provision.validator_id)
            {
                signer_indices.push(idx);
                signatures.push(provision.signature.clone());
            }
        }

        // Get block height from the first provision (all should be same height)
        let block_height = provisions
            .first()
            .map(|p| p.block_height)
            .unwrap_or(BlockHeight(0));

        // Deduplicate entries from all provisions
        // All provisions for the same tx/shard should have identical entries,
        // but we take from the first provision to be safe.
        let entries: Vec<StateEntry> = provisions
            .first()
            .map(|p| p.entries.as_ref().clone())
            .unwrap_or_default();

        Action::AggregateCommitmentProof {
            tx_hash,
            source_shard,
            block_height,
            entries,
            signatures,
            signer_indices,
            committee_size,
        }
    }

    /// Clean up all state for a transaction.
    fn cleanup_tx(&mut self, tx_hash: &Hash) {
        // Remove registration
        self.registered_txs.remove(tx_hash);

        // Remove pending verifications
        if let Some(validators) = self.pending_verifications_by_tx.remove(tx_hash) {
            for validator_id in validators {
                self.pending_verifications.remove(&(*tx_hash, validator_id));
            }
        }

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

            Event::ProvisionSignatureVerified { provision, valid } => {
                Some(self.on_provision_verified(provision.clone(), *valid))
            }

            // Callback from signature aggregation
            Event::CommitmentProofAggregated {
                tx_hash,
                source_shard,
                commitment_proof,
            } => Some(self.on_commitment_proof_aggregated(
                *tx_hash,
                *source_shard,
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
    use hyperscale_types::{
        KeyPair, PartitionNumber, Signature, StateEntry, StaticTopology, ValidatorInfo,
        ValidatorSet,
    };

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
            .map(|node_id| StateEntry::new(node_id, PartitionNumber(0), vec![], None))
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
    // Core Lifecycle Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_provision_received_queues_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        let provision = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        let actions = coordinator.on_provision_received(provision);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::VerifyProvisionSignature { .. }
        ));
    }

    #[test]
    fn test_provision_verified_valid_stores_provision() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        let provision = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        coordinator.on_provision_received(provision.clone());

        // Simulate verification callback
        coordinator.on_provision_verified(provision, true);

        // Should be stored
        assert!(coordinator.has_any_verified_provisions(&tx_hash));

        // Reverse index should be updated
        let txs = coordinator.txs_with_provisions_from(ShardGroupId(1));
        assert!(txs.is_some());
        assert!(txs.unwrap().contains(&tx_hash));
    }

    #[test]
    fn test_provision_verified_invalid_discarded() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        let provision = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        coordinator.on_provision_received(provision.clone());

        // Simulate failed verification
        coordinator.on_provision_verified(provision, false);

        // Should NOT be stored
        assert!(!coordinator.has_any_verified_provisions(&tx_hash));
    }

    #[test]
    fn test_remote_tx_auto_registered() {
        // Remote TXs (provisions for unregistered TXs) are now auto-registered
        // for livelock cycle detection. No buffering occurs.
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let provision = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));

        // Receive provision for unregistered (remote) TX
        let actions = coordinator.on_provision_received(provision);

        // Should auto-register and queue for verification (not buffer)
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::VerifyProvisionSignature { .. }
        ));

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
        coordinator.on_provision_received(provision.clone());
        assert!(coordinator.is_registered(&tx_hash));

        // Auto-registration only requires shard 1 (from the provision)
        let auto_reg = coordinator.get_registration(&tx_hash).unwrap();
        assert!(auto_reg.required_shards.contains(&ShardGroupId(1)));

        // Now explicitly register with different requirements
        let registration = make_registration(vec![ShardGroupId(1), ShardGroupId(2)], 2);
        let actions = coordinator.on_tx_registered(tx_hash, registration);

        // No verification actions (provision already processed)
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

        // First provision
        let p1 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        coordinator.on_provision_received(p1.clone());
        coordinator.on_provision_verified(p1, true);

        // Not yet at quorum
        assert!(!coordinator.has_quorum(&tx_hash));

        // Second provision
        let p2 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(4));
        coordinator.on_provision_received(p2.clone());
        coordinator.on_provision_verified(p2, true);

        // Now at quorum (single shard requirement)
        assert!(coordinator.has_quorum(&tx_hash));
    }

    #[test]
    fn test_all_shards_quorum_marks_ready() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        // Require 1 provision from shards 1 and 2 (we only have validators 0-5)
        // Let's just require shard 1 with threshold 1 for simplicity
        let registration = make_registration(vec![ShardGroupId(1)], 1);
        coordinator.on_tx_registered(tx_hash, registration);

        let p = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        coordinator.on_provision_received(p.clone());
        coordinator.on_provision_verified(p, true);

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

        // First receive
        let actions1 = coordinator.on_provision_received(provision.clone());
        assert_eq!(actions1.len(), 1);

        // Duplicate (pending verification)
        let actions2 = coordinator.on_provision_received(provision.clone());
        assert!(actions2.is_empty());

        // Verify and try again
        coordinator.on_provision_verified(provision.clone(), true);
        let actions3 = coordinator.on_provision_received(provision);
        assert!(actions3.is_empty());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Query Method Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_has_any_verified_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)], 2);
        coordinator.on_tx_registered(tx_hash, registration);

        assert!(!coordinator.has_any_verified_provisions(&tx_hash));

        let provision = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        coordinator.on_provision_received(provision.clone());
        coordinator.on_provision_verified(provision, true);

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
        coordinator.on_provision_verified(provision, true);

        let nodes = coordinator.provision_nodes(tx_hash, ShardGroupId(1));
        assert!(nodes.contains(&node1));
        assert!(nodes.contains(&node2));
    }

    #[test]
    fn test_cross_shard_pending_count() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        assert_eq!(coordinator.cross_shard_pending_count(), 0);

        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");

        coordinator.on_tx_registered(tx1, make_registration(vec![ShardGroupId(1)], 1));
        assert_eq!(coordinator.cross_shard_pending_count(), 1);

        coordinator.on_tx_registered(tx2, make_registration(vec![ShardGroupId(1)], 1));
        assert_eq!(coordinator.cross_shard_pending_count(), 2);
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

        // Add two verified provisions
        let provision1 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(3));
        coordinator.on_provision_received(provision1.clone());
        coordinator.on_provision_verified(provision1, true);

        let provision2 = make_provision(tx_hash, ShardGroupId(1), ValidatorId(4));
        coordinator.on_provision_received(provision2.clone());
        coordinator.on_provision_verified(provision2, true);

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
        coordinator.on_provision_verified(provision, true);

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
        coordinator.on_provision_verified(provision, true);

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

    // ═══════════════════════════════════════════════════════════════════════
    // Backpressure Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_at_backpressure_limit() {
        let topology = make_test_topology(ShardGroupId(0));
        let config = ProvisionConfig::with_max_pending(2);
        let mut coordinator = ProvisionCoordinator::with_config(ShardGroupId(0), topology, config);

        assert!(!coordinator.at_backpressure_limit());

        // Add transactions up to limit
        coordinator.on_tx_registered(
            Hash::from_bytes(b"tx1"),
            make_registration(vec![ShardGroupId(1)], 1),
        );
        coordinator.on_tx_registered(
            Hash::from_bytes(b"tx2"),
            make_registration(vec![ShardGroupId(1)], 1),
        );

        assert!(coordinator.at_backpressure_limit());
    }

    #[test]
    fn test_backpressure_disabled() {
        let topology = make_test_topology(ShardGroupId(0));
        let config = ProvisionConfig::disabled();
        let mut coordinator = ProvisionCoordinator::with_config(ShardGroupId(0), topology, config);

        // Add many transactions
        for i in 0..100 {
            coordinator.on_tx_registered(
                Hash::from_bytes(format!("tx{}", i).as_bytes()),
                make_registration(vec![ShardGroupId(1)], 1),
            );
        }

        // Should never be at limit when disabled
        assert!(!coordinator.at_backpressure_limit());
    }
}
