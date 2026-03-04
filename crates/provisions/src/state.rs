//! ProvisionCoordinator sub-state machine for centralized provision management.
//!
//! This module implements the provision coordination system that tracks all
//! cross-shard provisions, manages QC + merkle proof verification, and emits
//! quorum events for downstream consumers.
//!
//! ## Provision Flow
//!
//! The source shard proposer broadcasts a `StateProvision` containing JMT
//! inclusion proofs. The target shard joins with remote block headers, then
//! dispatches `VerifyStateProvision` to verify the QC signature and
//! merkle proofs against the committed state root.

use hyperscale_core::{Action, ProtocolEvent};
use hyperscale_types::{
    BlockHeight, CommitmentProof, CommittedBlockHeader, Hash, NodeId, ShardGroupId, StateProvision,
    Topology, ValidatorId,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Number of block heights to retain remote headers below each shard's tip.
/// When a new header arrives, headers from the same shard older than
/// `tip - REMOTE_HEADER_RETENTION_BLOCKS` are pruned from both the unverified
/// and verified header buffers.
const REMOTE_HEADER_RETENTION_BLOCKS: u64 = 100;

/// Registration information for a cross-shard transaction.
///
/// Created by ExecutionState when a cross-shard transaction is committed,
/// and used by ProvisionCoordinator to track provision progress.
#[derive(Debug, Clone)]
pub struct TxRegistration {
    /// Shards we need provisions from.
    pub required_shards: BTreeSet<ShardGroupId>,

    /// Block height when registered (for potential timeout).
    pub registered_at: BlockHeight,
}

/// Centralized provision coordination.
///
/// Responsibilities:
/// - Receive provisions from the source shard proposer
/// - Join provisions with remote block headers
/// - Dispatch QC + merkle proof verification
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
    /// Maps tx_hash -> registration info (required shards, etc.)
    registered_txs: HashMap<Hash, TxRegistration>,

    // ═══════════════════════════════════════════════════════════════════
    // Reverse Indexes
    // ═══════════════════════════════════════════════════════════════════
    /// Reverse index: source_shard -> tx_hashes with verified provisions from that shard.
    /// Used by livelock for efficient cycle detection.
    txs_by_source_shard: HashMap<ShardGroupId, HashSet<Hash>>,

    // ═══════════════════════════════════════════════════════════════════
    // Remote Block Headers
    // ═══════════════════════════════════════════════════════════════════
    /// Unverified committed block headers from remote shards.
    ///
    /// Outer key: `(shard, height)` for O(1) lookup when a provision arrives.
    /// Inner key: `sender` — one slot per validator. The sender's BLS signature
    /// was verified by NodeLoop but the QC has NOT been verified yet (deferred
    /// until a provision needs this header).
    ///
    /// Pruned when a header from the same shard arrives with a height
    /// exceeding the current tip by more than `REMOTE_HEADER_RETENTION_BLOCKS`.
    unverified_remote_headers:
        HashMap<(ShardGroupId, BlockHeight), HashMap<ValidatorId, CommittedBlockHeader>>,

    /// Verified committed block headers from remote shards.
    ///
    /// Promoted from `unverified_remote_headers` when QC verification succeeds
    /// (lazy verification on provision arrival).
    /// Indexed by `(shard, height)` for efficient lookup.
    verified_remote_headers: HashMap<(ShardGroupId, BlockHeight), CommittedBlockHeader>,

    /// Highest seen block height per remote shard.
    /// Used for pruning old entries from both header buffers.
    remote_header_tips: HashMap<ShardGroupId, BlockHeight>,

    // ═══════════════════════════════════════════════════════════════════
    // Verified Provisions
    // ═══════════════════════════════════════════════════════════════════
    /// Provisions waiting for their corresponding remote block header.
    /// Keyed by (source_shard, block_height) since that's how we match to headers.
    pending_provisions: HashMap<(ShardGroupId, BlockHeight), Vec<StateProvision>>,

    /// Verified provisions with their commitment proofs.
    /// Keyed by tx_hash -> (source_shard -> (provision, commitment_proof)).
    verified_provisions: HashMap<Hash, HashMap<ShardGroupId, (StateProvision, CommitmentProof)>>,

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
            .field(
                "unverified_remote_headers",
                &self.unverified_remote_headers.len(),
            )
            .field(
                "verified_remote_headers",
                &self.verified_remote_headers.len(),
            )
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
            txs_by_source_shard: HashMap::new(),
            unverified_remote_headers: HashMap::new(),
            verified_remote_headers: HashMap::new(),
            remote_header_tips: HashMap::new(),
            pending_provisions: HashMap::new(),
            verified_provisions: HashMap::new(),
            now: Duration::ZERO,
        }
    }

    /// Set the current time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
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
        for cert in &block.certificates {
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
    // Remote Block Header Tracking
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a committed block header received from a remote shard.
    ///
    /// The sender's BLS signature was already verified by NodeLoop.
    /// Headers are stored in an unverified buffer keyed by `(shard, height, sender)`.
    /// QC verification is deferred until a provision arrives that needs this header.
    ///
    /// Structural pre-checks are performed:
    /// - `qc.block_hash == header.hash()` (certifying QC matches header)
    /// - `qc.shard_group_id == header.shard_group_id` (shard consistency)
    pub fn on_remote_block_committed(
        &mut self,
        committed_header: CommittedBlockHeader,
        sender: ValidatorId,
    ) -> Vec<Action> {
        let shard = committed_header.shard_group_id();
        let height = committed_header.height();

        // Ignore headers from our own shard (we already have these locally).
        if shard == self.local_shard {
            return vec![];
        }

        // Structural pre-check: certifying QC must match header hash.
        let header_hash = committed_header.header.hash();
        if committed_header.qc.block_hash != header_hash {
            warn!(
                shard = shard.0,
                height = height.0,
                sender = sender.0,
                "Rejected remote header: QC block_hash does not match header hash"
            );
            return vec![];
        }

        // Structural pre-check: QC shard must match header shard.
        if committed_header.qc.shard_group_id != shard {
            warn!(
                shard = shard.0,
                height = height.0,
                sender = sender.0,
                qc_shard = committed_header.qc.shard_group_id.0,
                "Rejected remote header: QC shard_group_id does not match header shard"
            );
            return vec![];
        }

        debug!(
            shard = shard.0,
            height = height.0,
            sender = sender.0,
            state_root = %committed_header.state_root(),
            "Received remote committed block header (unverified)"
        );

        // Insert into unverified buffer — one slot per (shard, height, sender).
        // Overwrites previous entry from same sender for same (shard, height).
        self.unverified_remote_headers
            .entry((shard, height))
            .or_default()
            .insert(sender, committed_header.clone());

        // Update tip and prune old headers for this shard.
        let tip = self
            .remote_header_tips
            .entry(shard)
            .or_insert(BlockHeight(0));
        if height > *tip {
            *tip = height;
        }
        let cutoff = tip.0.saturating_sub(REMOTE_HEADER_RETENTION_BLOCKS);
        if cutoff > 0 {
            self.unverified_remote_headers
                .retain(|&(s, h), _| s != shard || h.0 >= cutoff);
            self.verified_remote_headers
                .retain(|&(s, h), _| s != shard || h.0 >= cutoff);
        }

        // Check if we have any buffered provisions waiting for this header
        let mut actions = vec![];
        if let Some(provisions) = self.pending_provisions.remove(&(shard, height)) {
            debug!(
                shard = shard.0,
                height = height.0,
                pending_count = provisions.len(),
                "Found buffered provisions for newly arrived header"
            );
            for provision in provisions {
                actions
                    .extend(self.emit_provision_verification(provision, committed_header.clone()));
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // State Provision Lifecycle
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a state provision received from the source shard proposer.
    ///
    /// Joins the provision with the corresponding remote block header:
    /// - If header found in unverified buffer: emit verification action
    /// - If header not found: buffer provision until header arrives
    pub fn on_state_provision_received(&mut self, provision: StateProvision) -> Vec<Action> {
        let tx_hash = provision.transaction_hash;
        let source_shard = provision.source_shard;
        let block_height = provision.block_height;

        debug!(
            tx_hash = %tx_hash,
            source_shard = source_shard.0,
            block_height = block_height.0,
            entries = provision.entries.len(),
            "State provision received"
        );

        // Ignore provisions from our own shard
        if source_shard == self.local_shard {
            return vec![];
        }

        // Auto-register if not already registered (for remote TXs / cycle detection)
        self.registered_txs.entry(tx_hash).or_insert_with(|| {
            let mut required_shards = BTreeSet::new();
            required_shards.insert(source_shard);

            TxRegistration {
                required_shards,
                registered_at: BlockHeight(0),
            }
        });

        // Already have a verified provision for this (tx, shard)?
        if self
            .verified_provisions
            .get(&tx_hash)
            .and_then(|by_shard| by_shard.get(&source_shard))
            .is_some()
        {
            trace!(
                tx_hash = %tx_hash,
                source_shard = source_shard.0,
                "Ignoring provision (already verified for this shard)"
            );
            return vec![];
        }

        // Look for a matching remote header — check unverified first, then verified.
        // A prior provision for the same (shard, height) may have already promoted the
        // header to verified_remote_headers, so we must check both buffers.
        let header = self
            .unverified_remote_headers
            .get(&(source_shard, block_height))
            .and_then(|by_sender| by_sender.values().next())
            .cloned()
            .or_else(|| {
                self.verified_remote_headers
                    .get(&(source_shard, block_height))
                    .cloned()
            });

        if let Some(committed_header) = header {
            // Header found — emit async QC + merkle proof verification
            self.emit_provision_verification(provision, committed_header)
        } else {
            // No header yet — buffer the provision
            debug!(
                tx_hash = %tx_hash,
                source_shard = source_shard.0,
                block_height = block_height.0,
                "Buffering provision (waiting for remote header)"
            );
            self.pending_provisions
                .entry((source_shard, block_height))
                .or_default()
                .push(provision);
            vec![]
        }
    }

    /// Emit a VerifyStateProvision action for async verification.
    fn emit_provision_verification(
        &self,
        provision: StateProvision,
        committed_header: CommittedBlockHeader,
    ) -> Vec<Action> {
        let source_shard = provision.source_shard;
        let tx_hash = provision.transaction_hash;

        // Resolve ALL committee public keys in order for QC verification.
        // verify_qc_signature filters internally by the signer bitfield,
        // so it needs the full committee array (matching BFT's collect_qc_signer_keys).
        let committee = self.topology.committee_for_shard(source_shard);
        let mut total_voting_power = 0u64;
        let committee_public_keys: Vec<_> = committee
            .iter()
            .map(|&validator_id| {
                self.topology
                    .public_key(validator_id)
                    .expect("committee member must have a public key")
            })
            .collect();

        // Compute voting power from signers only
        for idx in committed_header.qc.signers.set_indices() {
            if let Some(&validator_id) = committee.get(idx) {
                total_voting_power += self.topology.voting_power(validator_id).unwrap_or(0);
            }
        }

        let quorum_threshold = self.topology.quorum_threshold_for_shard(source_shard);

        vec![Action::VerifyStateProvision {
            tx_hash,
            source_shard,
            committed_header,
            provision,
            committee_public_keys,
            total_voting_power,
            quorum_threshold,
        }]
    }

    /// Handle state provision verification result.
    ///
    /// On success: build CommitmentProof, track quorum, emit events.
    pub fn on_state_provision_verified(
        &mut self,
        tx_hash: Hash,
        source_shard: ShardGroupId,
        valid: bool,
        provision: StateProvision,
    ) -> Vec<Action> {
        if !valid {
            warn!(
                tx_hash = %tx_hash,
                source_shard = source_shard.0,
                "State provision verification failed"
            );
            return vec![];
        }

        debug!(
            tx_hash = %tx_hash,
            source_shard = source_shard.0,
            entries = provision.entries.len(),
            "State provision verified successfully"
        );

        // Find the remote header — check verified first (may have been promoted
        // by a previous provision from the same block), then unverified.
        let block_height = provision.block_height;
        let header = if let Some(h) = self
            .verified_remote_headers
            .get(&(source_shard, block_height))
            .cloned()
        {
            // Already promoted by a previous provision verification
            Some(h)
        } else if let Some(by_sender) = self
            .unverified_remote_headers
            .remove(&(source_shard, block_height))
        {
            // Take first header and promote to verified
            let h = by_sender.into_values().next().unwrap();
            self.verified_remote_headers
                .insert((source_shard, block_height), h.clone());

            // Update tip tracking
            let tip = self
                .remote_header_tips
                .entry(source_shard)
                .or_insert(BlockHeight(0));
            if block_height > *tip {
                *tip = block_height;
            }

            Some(h)
        } else {
            None
        };

        let Some(header) = header else {
            warn!(
                tx_hash = %tx_hash,
                source_shard = source_shard.0,
                "State provision verified but no matching header found"
            );
            return vec![];
        };

        // Build CommitmentProof from provision + header
        let proof = CommitmentProof::new(
            tx_hash,
            source_shard,
            self.local_shard,
            provision.block_height,
            provision.block_timestamp,
            header.state_root(),
            header.qc.clone(),
            (*provision.entries).clone(),
            (*provision.merkle_proofs).clone(),
        );

        // Store provision and proof together
        self.verified_provisions
            .entry(tx_hash)
            .or_default()
            .insert(source_shard, (provision.clone(), proof.clone()));

        // Update reverse index for cycle detection
        self.txs_by_source_shard
            .entry(source_shard)
            .or_default()
            .insert(tx_hash);

        let mut actions = vec![];

        // Emit provision verified for this shard (used by livelock for cycle detection)
        actions.push(Action::Continuation(ProtocolEvent::ProvisionAccepted {
            tx_hash,
            source_shard,
            commitment_proof: proof,
        }));

        // Check if ALL required shards have verified provisions
        if self.all_shards_verified(tx_hash) {
            let all_provisions: Vec<StateProvision> = self
                .verified_provisions
                .get(&tx_hash)
                .map(|by_shard| {
                    by_shard
                        .values()
                        .map(|(provision, _)| provision.clone())
                        .collect()
                })
                .unwrap_or_default();

            debug!(
                tx_hash = %tx_hash,
                "All shards verified - ready for execution"
            );

            actions.push(Action::Continuation(ProtocolEvent::ProvisioningComplete {
                tx_hash,
                provisions: all_provisions,
            }));
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Query Methods (for other modules)
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if a transaction has any verified provisions.
    ///
    /// Used by backpressure: if true, another shard has committed,
    /// so we must cooperate regardless of limits.
    pub fn has_any_verified_provisions(&self, tx_hash: &Hash) -> bool {
        self.verified_provisions.contains_key(tx_hash)
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
        if let Some((_, proof)) = self
            .verified_provisions
            .get(&tx_hash)
            .and_then(|by_shard| by_shard.get(&shard))
        {
            return proof.nodes();
        }
        HashSet::new()
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
    /// Returns the first available proof from verified provisions.
    /// This is sufficient for backpressure purposes - it proves another shard committed.
    pub fn build_commitment_proof(&self, tx_hash: &Hash) -> Option<CommitmentProof> {
        self.verified_provisions
            .get(tx_hash)
            .and_then(|by_shard| by_shard.values().next().map(|(_, proof)| proof.clone()))
    }

    /// Look up a verified remote committed block header by shard and height.
    pub fn get_remote_header(
        &self,
        shard: ShardGroupId,
        height: BlockHeight,
    ) -> Option<&CommittedBlockHeader> {
        self.verified_remote_headers.get(&(shard, height))
    }

    /// Get the number of individual unverified remote headers in the buffer.
    pub fn unverified_remote_header_count(&self) -> usize {
        self.unverified_remote_headers
            .values()
            .map(|by_sender| by_sender.len())
            .sum()
    }

    /// Get the number of verified remote headers.
    pub fn verified_remote_header_count(&self) -> usize {
        self.verified_remote_headers.len()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internal Helper Methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Check if all required shards have a verified provision.
    fn all_shards_verified(&self, tx_hash: Hash) -> bool {
        let Some(registration) = self.registered_txs.get(&tx_hash) else {
            return false;
        };

        let Some(verified) = self.verified_provisions.get(&tx_hash) else {
            return false;
        };

        registration
            .required_shards
            .iter()
            .all(|shard| verified.contains_key(shard))
    }

    /// Clean up all state for a transaction.
    fn cleanup_tx(&mut self, tx_hash: &Hash) {
        // Remove registration
        self.registered_txs.remove(tx_hash);

        // Remove verified provisions and update reverse index
        if let Some(by_shard) = self.verified_provisions.remove(tx_hash) {
            for shard in by_shard.keys() {
                if let Some(txs) = self.txs_by_source_shard.get_mut(shard) {
                    txs.remove(tx_hash);
                }
            }
        }

        // Remove pending provisions that reference this tx
        self.pending_provisions.retain(|_, provisions| {
            provisions.retain(|p| p.transaction_hash != *tx_hash);
            !provisions.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        bls_keypair_from_seed, BlockHeader, Bls12381G1PrivateKey, QuorumCertificate,
        StaticTopology, ValidatorInfo, ValidatorSet,
    };

    fn make_test_topology(local_shard: ShardGroupId) -> Arc<dyn Topology> {
        // Create deterministic BLS keypairs for 6 validators (2 shards × 3 validators)
        let keypairs: Vec<Bls12381G1PrivateKey> = (0..6)
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                seed[1] = 42; // Fixed seed for determinism
                bls_keypair_from_seed(&seed)
            })
            .collect();

        let validators: Vec<_> = keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| ValidatorInfo {
                validator_id: ValidatorId(i as u64),
                public_key: kp.public_key(),
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

    fn make_registration(required_shards: Vec<ShardGroupId>) -> TxRegistration {
        TxRegistration {
            required_shards: required_shards.into_iter().collect(),
            registered_at: BlockHeight(1),
        }
    }

    #[test]
    fn test_build_commitment_proof_returns_none_without_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        assert!(coordinator.build_commitment_proof(&tx_hash).is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tx_aborted_cleans_up_state() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)]);
        coordinator.on_tx_registered(tx_hash, registration);

        // Abort before any provisions
        coordinator.on_tx_aborted(&tx_hash);

        assert!(!coordinator.is_registered(&tx_hash));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_tx_completed_cleans_up_state() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"test_tx");
        let registration = make_registration(vec![ShardGroupId(1)]);
        coordinator.on_tx_registered(tx_hash, registration);

        // Verify registration exists
        assert!(coordinator.is_registered(&tx_hash));

        // Complete transaction
        coordinator.on_tx_completed(&tx_hash);

        // All state should be cleaned up
        assert!(!coordinator.is_registered(&tx_hash));
        assert!(!coordinator.has_any_verified_provisions(&tx_hash));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Remote Block Header Tracking Tests (Unverified Buffer)
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a CommittedBlockHeader with a QC whose block_hash matches
    /// the header's hash (structural invariant from commit 638c352).
    fn make_committed_header(shard: ShardGroupId, height: u64) -> CommittedBlockHeader {
        let header = BlockHeader {
            shard_group_id: shard,
            height: BlockHeight(height),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1000 + height,
            round: 0,
            is_fallback: false,
            state_root: Hash::from_bytes(format!("root_{shard}_{height}").as_bytes()),
            state_version: height,
            transaction_root: Hash::ZERO,
        };
        let header_hash = header.hash();
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = header_hash;
        qc.shard_group_id = shard;
        CommittedBlockHeader { header, qc }
    }

    #[test]
    fn test_remote_header_stored_in_unverified_buffer() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let header = make_committed_header(ShardGroupId(1), 10);
        let sender = ValidatorId(3);
        let actions = coordinator.on_remote_block_committed(header, sender);
        assert!(actions.is_empty());

        // Should be in unverified buffer
        assert_eq!(coordinator.unverified_remote_header_count(), 1);
        // Should NOT be in verified buffer (get_remote_header reads from verified only)
        assert!(coordinator
            .get_remote_header(ShardGroupId(1), BlockHeight(10))
            .is_none());
    }

    #[test]
    fn test_remote_header_from_own_shard_ignored() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let header = make_committed_header(ShardGroupId(0), 10);
        coordinator.on_remote_block_committed(header, ValidatorId(0));

        assert_eq!(coordinator.unverified_remote_header_count(), 0);
    }

    #[test]
    fn test_remote_header_multiple_shards_and_heights() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let sender = ValidatorId(3);
        coordinator.on_remote_block_committed(make_committed_header(ShardGroupId(1), 10), sender);
        coordinator.on_remote_block_committed(make_committed_header(ShardGroupId(1), 11), sender);
        // Use a different sender for shard 2 (since our topology has different validators per shard)
        coordinator
            .on_remote_block_committed(make_committed_header(ShardGroupId(2), 10), ValidatorId(4));

        assert_eq!(coordinator.unverified_remote_header_count(), 3);
    }

    #[test]
    fn test_remote_header_same_shard_height_different_validators_stores_both() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let header1 = make_committed_header(ShardGroupId(1), 10);
        let header2 = make_committed_header(ShardGroupId(1), 10);

        // Two different validators send headers for the same (shard, height)
        coordinator.on_remote_block_committed(header1, ValidatorId(3));
        coordinator.on_remote_block_committed(header2, ValidatorId(4));

        // Both should be stored (different sender keys)
        assert_eq!(coordinator.unverified_remote_header_count(), 2);
    }

    #[test]
    fn test_remote_header_same_shard_height_same_validator_overwrites() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let sender = ValidatorId(3);
        coordinator.on_remote_block_committed(make_committed_header(ShardGroupId(1), 10), sender);
        coordinator.on_remote_block_committed(make_committed_header(ShardGroupId(1), 10), sender);

        // Same (shard, height, sender) — should overwrite, not duplicate
        assert_eq!(coordinator.unverified_remote_header_count(), 1);
    }

    #[test]
    fn test_remote_header_rejects_mismatched_qc_block_hash() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        // Create a header where the QC block_hash doesn't match the header hash
        let header = BlockHeader {
            shard_group_id: ShardGroupId(1),
            height: BlockHeight(10),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1010,
            round: 0,
            is_fallback: false,
            state_root: Hash::from_bytes(b"root"),
            state_version: 10,
            transaction_root: Hash::ZERO,
        };
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = Hash::from_bytes(b"wrong_hash"); // Mismatch!
        qc.shard_group_id = ShardGroupId(1);
        let committed = CommittedBlockHeader { header, qc };

        let actions = coordinator.on_remote_block_committed(committed, ValidatorId(3));
        assert!(actions.is_empty());
        assert_eq!(coordinator.unverified_remote_header_count(), 0);
    }

    #[test]
    fn test_remote_header_rejects_mismatched_shard_group_id() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        // Create a header where the QC shard doesn't match the header shard
        let header = BlockHeader {
            shard_group_id: ShardGroupId(1),
            height: BlockHeight(10),
            parent_hash: Hash::from_bytes(b"parent"),
            parent_qc: QuorumCertificate::genesis(),
            proposer: ValidatorId(0),
            timestamp: 1010,
            round: 0,
            is_fallback: false,
            state_root: Hash::from_bytes(b"root"),
            state_version: 10,
            transaction_root: Hash::ZERO,
        };
        let header_hash = header.hash();
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = header_hash;
        qc.shard_group_id = ShardGroupId(2); // Mismatch!
        let committed = CommittedBlockHeader { header, qc };

        let actions = coordinator.on_remote_block_committed(committed, ValidatorId(3));
        assert!(actions.is_empty());
        assert_eq!(coordinator.unverified_remote_header_count(), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Provision Lifecycle Tests
    // ═══════════════════════════════════════════════════════════════════════

    fn make_provision(
        tx_hash: Hash,
        source_shard: ShardGroupId,
        target_shard: ShardGroupId,
        height: u64,
    ) -> StateProvision {
        StateProvision {
            transaction_hash: tx_hash,
            target_shard,
            source_shard,
            block_height: BlockHeight(height),
            block_timestamp: 1000 + height,
            state_version: height,
            entries: Arc::new(vec![]),
            merkle_proofs: Arc::new(vec![]),
        }
    }

    #[test]
    fn test_provision_received_with_header_emits_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // First: header arrives
        let header = make_committed_header(source_shard, 10);
        coordinator.on_remote_block_committed(header, ValidatorId(3));

        // Then: provision arrives — should emit VerifyStateProvision
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provision_received(provision);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyStateProvision { tx_hash: h, .. } if *h == tx_hash
        ));

        // Should auto-register the tx
        assert!(coordinator.is_registered(&tx_hash));
    }

    #[test]
    fn test_provision_received_without_header_buffers() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Provision arrives before header — should buffer
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provision_received(provision);

        assert!(actions.is_empty());
        // Should still auto-register
        assert!(coordinator.is_registered(&tx_hash));
    }

    #[test]
    fn test_header_arrival_triggers_buffered_provision_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Provision arrives first — buffered
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provision_received(provision);

        // Then header arrives — should trigger verification of buffered provision
        let header = make_committed_header(source_shard, 10);
        let actions = coordinator.on_remote_block_committed(header, ValidatorId(3));

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyStateProvision { tx_hash: h, .. } if *h == tx_hash
        ));
    }

    #[test]
    fn test_provision_from_own_shard_ignored() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let provision = make_provision(
            Hash::from_bytes(b"tx1"),
            ShardGroupId(0), // own shard
            ShardGroupId(1),
            10,
        );
        let actions = coordinator.on_state_provision_received(provision);

        assert!(actions.is_empty());
        // Should NOT auto-register
        assert!(!coordinator.is_registered(&Hash::from_bytes(b"tx1")));
    }

    #[test]
    fn test_duplicate_provision_ignored_after_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Setup: header + provision + verification
        let header = make_committed_header(source_shard, 10);
        coordinator.on_remote_block_committed(header, ValidatorId(3));
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provision_received(provision.clone());

        // Simulate successful verification
        coordinator.on_state_provision_verified(tx_hash, source_shard, true, provision.clone());

        // Second provision for same (tx, shard) should be ignored
        let actions = coordinator.on_state_provision_received(provision);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_provision_verified_builds_commitment_proof() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Setup
        let header = make_committed_header(source_shard, 10);
        coordinator.on_remote_block_committed(header, ValidatorId(3));
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provision_received(provision.clone());

        // Verify
        let actions =
            coordinator.on_state_provision_verified(tx_hash, source_shard, true, provision);

        // Should emit ProvisionAccepted
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionAccepted {
                tx_hash: h,
                source_shard: s,
                ..
            }) if *h == tx_hash && *s == source_shard
        )));

        // Should have a commitment proof
        assert!(coordinator.has_any_verified_provisions(&tx_hash));
        let proof = coordinator.build_commitment_proof(&tx_hash).unwrap();
        assert_eq!(proof.tx_hash, tx_hash);
        assert_eq!(proof.source_shard, source_shard);
    }

    #[test]
    fn test_provision_verified_invalid_does_not_store() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        let header = make_committed_header(source_shard, 10);
        coordinator.on_remote_block_committed(header, ValidatorId(3));
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provision_received(provision.clone());

        // Verification fails
        let actions =
            coordinator.on_state_provision_verified(tx_hash, source_shard, false, provision);

        assert!(actions.is_empty());
        assert!(!coordinator.has_any_verified_provisions(&tx_hash));
    }

    #[test]
    fn test_all_shards_verified_emits_provisioning_complete() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"tx1");
        let shard1 = ShardGroupId(1);
        let shard2 = ShardGroupId(2);

        // Register tx requiring provisions from two shards
        let registration = make_registration(vec![shard1, shard2]);
        coordinator.on_tx_registered(tx_hash, registration);

        // Verify first shard
        let header1 = make_committed_header(shard1, 10);
        coordinator.on_remote_block_committed(header1, ValidatorId(3));
        let prov1 = make_provision(tx_hash, shard1, ShardGroupId(0), 10);
        coordinator.on_state_provision_received(prov1.clone());
        let actions = coordinator.on_state_provision_verified(tx_hash, shard1, true, prov1);

        // Should NOT emit ProvisioningComplete yet (shard2 still pending)
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisioningComplete { .. })
        )));

        // Verify second shard
        let header2 = make_committed_header(shard2, 10);
        coordinator.on_remote_block_committed(header2, ValidatorId(4));
        let prov2 = make_provision(tx_hash, shard2, ShardGroupId(0), 10);
        coordinator.on_state_provision_received(prov2.clone());
        let actions = coordinator.on_state_provision_verified(tx_hash, shard2, true, prov2);

        // NOW should emit ProvisioningComplete
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisioningComplete { tx_hash: h, .. })
            if *h == tx_hash
        )));
    }

    #[test]
    fn test_provision_nodes_returns_node_ids() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Create a provision with entries that have valid node IDs
        let mut storage_key = Vec::with_capacity(6 + 20 + 30 + 1 + 1);
        storage_key.extend_from_slice(b"radix:");
        storage_key.extend_from_slice(&[0u8; 20]);
        storage_key.extend_from_slice(&[42u8; 30]); // node_id
        storage_key.push(0); // partition
        storage_key.push(0); // sort_key

        let entry = hyperscale_types::StateEntry::new(storage_key, Some(vec![1, 2, 3]));
        let mut provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        provision.entries = Arc::new(vec![entry]);
        provision.merkle_proofs = Arc::new(vec![hyperscale_types::SubstateInclusionProof::dummy()]);

        // Setup + verify
        let header = make_committed_header(source_shard, 10);
        coordinator.on_remote_block_committed(header, ValidatorId(3));
        coordinator.on_state_provision_received(provision.clone());
        coordinator.on_state_provision_verified(tx_hash, source_shard, true, provision);

        // Check node extraction
        let nodes = coordinator.provision_nodes(tx_hash, source_shard);
        assert_eq!(nodes.len(), 1);
        assert!(nodes.contains(&NodeId([42u8; 30])));
    }

    #[test]
    fn test_txs_with_provisions_from_tracks_reverse_index() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Before verification
        assert!(coordinator.txs_with_provisions_from(source_shard).is_none());

        // Setup + verify
        let header = make_committed_header(source_shard, 10);
        coordinator.on_remote_block_committed(header, ValidatorId(3));
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provision_received(provision.clone());
        coordinator.on_state_provision_verified(tx_hash, source_shard, true, provision);

        // After verification
        let txs = coordinator.txs_with_provisions_from(source_shard).unwrap();
        assert!(txs.contains(&tx_hash));
    }

    #[test]
    fn test_cleanup_removes_pending_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Buffer a provision (no header yet)
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provision_received(provision);

        // Abort the tx — should clean up pending provisions too
        coordinator.on_tx_aborted(&tx_hash);
        assert!(!coordinator.is_registered(&tx_hash));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Unverified Buffer Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_unverified_buffer_pruned_by_tip() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let sender = ValidatorId(3);
        // Store headers at heights 1..50 for shard 1
        for h in 1..=50 {
            coordinator
                .on_remote_block_committed(make_committed_header(ShardGroupId(1), h), sender);
        }
        assert_eq!(coordinator.unverified_remote_header_count(), 50);

        // Insert a header at height 200 — prunes entries below height 100
        coordinator.on_remote_block_committed(make_committed_header(ShardGroupId(1), 200), sender);

        // Only height 200 should remain (heights 1-50 are all below cutoff=100)
        assert_eq!(coordinator.unverified_remote_header_count(), 1);
    }
}
