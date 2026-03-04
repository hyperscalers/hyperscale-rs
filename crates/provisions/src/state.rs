//! ProvisionCoordinator sub-state machine for centralized provision management.
//!
//! This module implements the provision coordination system that tracks all
//! cross-shard provisions, manages QC + merkle proof verification, and emits
//! verification events for downstream consumers.
//!
//! ## Provision Flow
//!
//! The source shard proposer broadcasts a `StateProvision` batch containing JMT
//! inclusion proofs. The target shard joins with remote block headers, then
//! dispatches `VerifyStateProvisions` to verify the QC signature once and
//! merkle proofs per provision against the committed state root.

use hyperscale_core::{Action, ProtocolEvent, ProvisionVerificationResult};
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

/// Number of local committed blocks to wait before requesting missing provisions.
/// This gives the source shard proposer time to send provisions normally.
const PROVISION_FALLBACK_TIMEOUT_BLOCKS: u64 = 10;

/// Minimum interval (in local committed blocks) between retry requests for
/// the same missing provision, to avoid flooding the network.
const PROVISION_RETRY_INTERVAL_BLOCKS: u64 = 10;

/// Tracks an expected provision that hasn't arrived yet.
///
/// Created when a remote block header's `provision_targets` includes our shard,
/// indicating that provisions should be forthcoming. If they don't arrive within
/// `PROVISION_FALLBACK_TIMEOUT_BLOCKS`, a `RequestMissingProvisions` action is emitted.
#[derive(Debug, Clone)]
struct ExpectedProvision {
    /// Local committed height when we first discovered this expected provision.
    discovered_at: BlockHeight,
    /// Local committed height when we last requested this provision (for retry throttling).
    last_requested_at: Option<BlockHeight>,
    /// The block proposer from the remote shard, preferred peer for fallback requests.
    proposer: ValidatorId,
}

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
/// - Receive provision batches from the source shard proposer
/// - Join provisions with remote block headers
/// - Dispatch QC + merkle proof verification (QC once per batch, proofs per provision)
/// - Track verified provisions per (tx, shard)
/// - Notify consumers when all required provisions are verified
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
    // Expected Provision Tracking (fallback detection)
    // ═══════════════════════════════════════════════════════════════════
    /// Current local committed height (updated on each block commit).
    local_committed_height: BlockHeight,

    /// Expected provisions that haven't arrived yet.
    /// Keyed by `(source_shard, block_height)`. Populated when a remote
    /// header's `provision_targets` includes our shard. Cleared when
    /// provisions are verified or the associated transactions are cleaned up.
    expected_provisions: HashMap<(ShardGroupId, BlockHeight), ExpectedProvision>,

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
            local_committed_height: BlockHeight(0),
            expected_provisions: HashMap::new(),
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

    /// Handle block committed - cleanup completed/aborted transactions and
    /// check for timed-out expected provisions.
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

        // Update local committed height
        self.local_committed_height = block.header.height;

        // Check for timed-out expected provisions and emit fallback requests
        let mut actions = vec![];
        let current_height = self.local_committed_height.0;

        for (&(source_shard, block_height), expected) in self.expected_provisions.iter_mut() {
            let age = current_height.saturating_sub(expected.discovered_at.0);
            if age < PROVISION_FALLBACK_TIMEOUT_BLOCKS {
                continue;
            }

            // Check retry throttling
            if let Some(last_req) = expected.last_requested_at {
                let since_last = current_height.saturating_sub(last_req.0);
                if since_last < PROVISION_RETRY_INTERVAL_BLOCKS {
                    continue;
                }
            }

            warn!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                age_blocks = age,
                "Provision timeout — requesting missing provisions via fallback"
            );

            expected.last_requested_at = Some(self.local_committed_height);
            actions.push(Action::RequestMissingProvisions {
                source_shard,
                block_height,
                proposer: expected.proposer,
            });
        }

        actions
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

        // Track expected provisions: if this block's provision_targets includes
        // our shard, we expect provisions to arrive. If they don't arrive within
        // the timeout, we'll request them via fallback.
        if committed_header
            .header
            .provision_targets
            .contains(&self.local_shard)
        {
            let key = (shard, height);
            let proposer = committed_header.header.proposer;
            self.expected_provisions.entry(key).or_insert_with(|| {
                debug!(
                    shard = shard.0,
                    height = height.0,
                    proposer = proposer.0,
                    "Tracking expected provision (remote block targets our shard)"
                );
                ExpectedProvision {
                    discovered_at: self.local_committed_height,
                    last_requested_at: None,
                    proposer,
                }
            });
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
            actions.extend(
                self.emit_provision_verification(provisions, vec![committed_header.clone()]),
            );
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // State Provision Lifecycle
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a batch of state provisions received from a source shard proposer.
    ///
    /// All provisions in a batch share the same `(source_shard, block_height)`.
    /// Joins with the corresponding remote block header:
    /// - If a verified header exists: use it directly (single candidate)
    /// - If unverified headers exist: send all candidates for verification
    /// - If no header found: buffer provisions until header arrives
    pub fn on_state_provisions_received(&mut self, provisions: Vec<StateProvision>) -> Vec<Action> {
        if provisions.is_empty() {
            return vec![];
        }

        // All provisions in a batch share the same source shard and block height.
        let source_shard = provisions[0].source_shard;
        let block_height = provisions[0].block_height;

        debug!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            count = provisions.len(),
            "State provisions batch received"
        );

        // Ignore provisions from our own shard
        if source_shard == self.local_shard {
            return vec![];
        }

        // Filter: auto-register unknown txs, skip already-verified provisions
        let mut to_verify = Vec::with_capacity(provisions.len());
        for provision in provisions {
            let tx_hash = provision.transaction_hash;

            // Auto-register if not already registered (for remote TXs / cycle detection)
            self.registered_txs.entry(tx_hash).or_insert_with(|| {
                let mut required_shards = BTreeSet::new();
                required_shards.insert(source_shard);
                TxRegistration {
                    required_shards,
                    registered_at: BlockHeight(0),
                }
            });

            // Skip if already verified for this (tx, shard)
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
                continue;
            }

            to_verify.push(provision);
        }

        if to_verify.is_empty() {
            return vec![];
        }

        // Look for matching remote headers — check VERIFIED FIRST (skip QC
        // re-verification), then collect ALL unverified candidates.
        let key = (source_shard, block_height);

        if let Some(verified_header) = self.verified_remote_headers.get(&key).cloned() {
            // Header already promoted by prior verification — single candidate
            return self.emit_provision_verification(to_verify, vec![verified_header]);
        }

        if let Some(by_sender) = self.unverified_remote_headers.get(&key) {
            // Collect ALL unverified candidates (one per validator sender)
            let candidates: Vec<CommittedBlockHeader> = by_sender.values().cloned().collect();
            return self.emit_provision_verification(to_verify, candidates);
        }

        // No header yet — buffer all provisions
        debug!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            count = to_verify.len(),
            "Buffering provisions (waiting for remote header)"
        );
        self.pending_provisions
            .entry(key)
            .or_default()
            .extend(to_verify);
        vec![]
    }

    /// Emit a `VerifyStateProvisions` action for async batch verification.
    ///
    /// The QC is verified once across candidates; merkle proofs are checked
    /// per provision against the verified header's state root.
    fn emit_provision_verification(
        &self,
        provisions: Vec<StateProvision>,
        committed_headers: Vec<CommittedBlockHeader>,
    ) -> Vec<Action> {
        // All provisions in a batch share the same source shard.
        let source_shard = provisions[0].source_shard;

        // Resolve ALL committee public keys in order for QC verification.
        // verify_qc_signature filters internally by the signer bitfield,
        // so it needs the full committee array (matching BFT's collect_qc_signer_keys).
        let committee = self.topology.committee_for_shard(source_shard);
        let committee_public_keys: Vec<_> = committee
            .iter()
            .map(|&validator_id| {
                self.topology
                    .public_key(validator_id)
                    .expect("committee member must have a public key")
            })
            .collect();

        // Per-validator voting power (parallel to committee_public_keys).
        // The action handler computes total_voting_power per-candidate from QC signer indices.
        let committee_voting_power: Vec<u64> = committee
            .iter()
            .map(|&validator_id| self.topology.voting_power(validator_id).unwrap_or(0))
            .collect();

        let quorum_threshold = self.topology.quorum_threshold_for_shard(source_shard);

        vec![Action::VerifyStateProvisions {
            provisions,
            committed_headers,
            committee_public_keys,
            committee_voting_power,
            quorum_threshold,
        }]
    }

    /// Handle batch state provision verification results.
    ///
    /// For each valid provision: build CommitmentProof, store provision, emit events.
    /// Uses the verified header returned by the action handler directly (no re-lookup).
    pub fn on_state_provisions_verified(
        &mut self,
        results: Vec<ProvisionVerificationResult>,
        committed_header: Option<CommittedBlockHeader>,
    ) -> Vec<Action> {
        let mut actions = vec![];

        // Promote the verified header if we have one
        if let Some(ref header) = committed_header {
            let shard = header.header.shard_group_id;
            let height = header.header.height;
            let key = (shard, height);

            if let std::collections::hash_map::Entry::Vacant(e) =
                self.verified_remote_headers.entry(key)
            {
                e.insert(header.clone());
                // Remove unverified entries for this (shard, height)
                self.unverified_remote_headers.remove(&key);
            }

            // Clear expected provision tracking — provisions arrived and verified
            self.expected_provisions.remove(&key);
        }

        for result in results {
            let tx_hash = result.tx_hash;
            let source_shard = result.source_shard;

            if !result.valid {
                warn!(
                    tx_hash = %tx_hash,
                    source_shard = source_shard.0,
                    "State provision verification failed"
                );
                continue;
            }

            let Some(ref header) = committed_header else {
                warn!(
                    tx_hash = %tx_hash,
                    source_shard = source_shard.0,
                    "State provision marked valid but no committed header"
                );
                continue;
            };

            debug!(
                tx_hash = %tx_hash,
                source_shard = source_shard.0,
                entries = result.provision.entries.len(),
                "State provision verified successfully"
            );

            let provision = result.provision;

            // Build CommitmentProof from provision + verified header
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

            // Emit provision accepted (used by livelock for cycle detection)
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
            provision_targets: vec![],
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
            provision_targets: vec![],
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
            provision_targets: vec![],
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

    /// Helper: simulate successful verification for a single provision.
    fn make_verified_result(provision: StateProvision, valid: bool) -> ProvisionVerificationResult {
        ProvisionVerificationResult {
            tx_hash: provision.transaction_hash,
            source_shard: provision.source_shard,
            valid,
            provision,
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

        // Then: provision arrives — should emit VerifyStateProvisions
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(vec![provision]);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyStateProvisions { provisions, .. } if provisions[0].transaction_hash == tx_hash
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
        let actions = coordinator.on_state_provisions_received(vec![provision]);

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
        coordinator.on_state_provisions_received(vec![provision]);

        // Then header arrives — should trigger verification of buffered provision
        let header = make_committed_header(source_shard, 10);
        let actions = coordinator.on_remote_block_committed(header, ValidatorId(3));

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyStateProvisions { provisions, .. } if provisions[0].transaction_hash == tx_hash
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
        let actions = coordinator.on_state_provisions_received(vec![provision]);

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
        coordinator.on_remote_block_committed(header.clone(), ValidatorId(3));
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(vec![provision.clone()]);

        // Simulate successful verification
        let result = make_verified_result(provision.clone(), true);
        coordinator.on_state_provisions_verified(vec![result], Some(header));

        // Second provision for same (tx, shard) should be ignored
        let actions = coordinator.on_state_provisions_received(vec![provision]);
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
        coordinator.on_remote_block_committed(header.clone(), ValidatorId(3));
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(vec![provision.clone()]);

        // Verify
        let result = make_verified_result(provision, true);
        let actions = coordinator.on_state_provisions_verified(vec![result], Some(header));

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
        coordinator.on_state_provisions_received(vec![provision.clone()]);

        // Verification fails — no committed_header returned
        let result = make_verified_result(provision, false);
        let actions = coordinator.on_state_provisions_verified(vec![result], None);

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
        coordinator.on_remote_block_committed(header1.clone(), ValidatorId(3));
        let prov1 = make_provision(tx_hash, shard1, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(vec![prov1.clone()]);
        let result1 = make_verified_result(prov1, true);
        let actions = coordinator.on_state_provisions_verified(vec![result1], Some(header1));

        // Should NOT emit ProvisioningComplete yet (shard2 still pending)
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisioningComplete { .. })
        )));

        // Verify second shard
        let header2 = make_committed_header(shard2, 10);
        coordinator.on_remote_block_committed(header2.clone(), ValidatorId(4));
        let prov2 = make_provision(tx_hash, shard2, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(vec![prov2.clone()]);
        let result2 = make_verified_result(prov2, true);
        let actions = coordinator.on_state_provisions_verified(vec![result2], Some(header2));

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
        coordinator.on_remote_block_committed(header.clone(), ValidatorId(3));
        coordinator.on_state_provisions_received(vec![provision.clone()]);
        let result = make_verified_result(provision, true);
        coordinator.on_state_provisions_verified(vec![result], Some(header));

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
        coordinator.on_remote_block_committed(header.clone(), ValidatorId(3));
        let provision = make_provision(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(vec![provision.clone()]);
        let result = make_verified_result(provision, true);
        coordinator.on_state_provisions_verified(vec![result], Some(header));

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
        coordinator.on_state_provisions_received(vec![provision]);

        // Abort the tx — should clean up pending provisions too
        coordinator.on_tx_aborted(&tx_hash);
        assert!(!coordinator.is_registered(&tx_hash));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch Verification Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_provision_batch_emits_single_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let source_shard = ShardGroupId(1);
        let header = make_committed_header(source_shard, 10);
        coordinator.on_remote_block_committed(header, ValidatorId(3));

        // Send batch of 3 provisions from the same block
        let provisions: Vec<_> = (0..3)
            .map(|i| {
                make_provision(
                    Hash::from_bytes(format!("tx{i}").as_bytes()),
                    source_shard,
                    ShardGroupId(0),
                    10,
                )
            })
            .collect();

        let actions = coordinator.on_state_provisions_received(provisions);

        // Should emit exactly ONE VerifyStateProvisions action with all 3 provisions
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::VerifyStateProvisions { provisions, .. } => {
                assert_eq!(provisions.len(), 3);
            }
            other => panic!("Expected VerifyStateProvisions, got {:?}", other),
        }
    }

    #[test]
    fn test_provision_sends_all_unverified_candidates() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let source_shard = ShardGroupId(1);

        // Two different validators send headers for the same (shard, height)
        let header = make_committed_header(source_shard, 10);
        coordinator.on_remote_block_committed(header, ValidatorId(3));
        coordinator
            .on_remote_block_committed(make_committed_header(source_shard, 10), ValidatorId(4));
        assert_eq!(coordinator.unverified_remote_header_count(), 2);

        // Provision arrives — should send BOTH candidates
        let provision = make_provision(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(vec![provision]);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::VerifyStateProvisions {
                committed_headers, ..
            } => {
                assert_eq!(committed_headers.len(), 2);
            }
            other => panic!("Expected VerifyStateProvisions, got {:?}", other),
        }
    }

    #[test]
    fn test_provision_uses_verified_header_when_available() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let source_shard = ShardGroupId(1);
        let header = make_committed_header(source_shard, 10);
        coordinator.on_remote_block_committed(header.clone(), ValidatorId(3));

        // First provision verifies (promotes header to verified)
        let prov1 = make_provision(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(vec![prov1.clone()]);
        let result = make_verified_result(prov1, true);
        coordinator.on_state_provisions_verified(vec![result], Some(header.clone()));

        // Second provision for different tx at same (shard, height)
        let prov2 = make_provision(Hash::from_bytes(b"tx2"), source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(vec![prov2]);

        // Should send only the verified header (single candidate)
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::VerifyStateProvisions {
                committed_headers, ..
            } => {
                assert_eq!(committed_headers.len(), 1);
            }
            other => panic!("Expected VerifyStateProvisions, got {:?}", other),
        }
    }

    #[test]
    fn test_batch_partial_merkle_failure() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let source_shard = ShardGroupId(1);
        let header = make_committed_header(source_shard, 10);
        coordinator.on_remote_block_committed(header.clone(), ValidatorId(3));

        let prov_ok = make_provision(
            Hash::from_bytes(b"tx_ok"),
            source_shard,
            ShardGroupId(0),
            10,
        );
        let prov_bad = make_provision(
            Hash::from_bytes(b"tx_bad"),
            source_shard,
            ShardGroupId(0),
            10,
        );

        coordinator.on_state_provisions_received(vec![prov_ok.clone(), prov_bad.clone()]);

        // QC passes but one provision fails merkle proof
        let results = vec![
            make_verified_result(prov_ok.clone(), true),
            make_verified_result(prov_bad, false),
        ];
        let actions = coordinator.on_state_provisions_verified(results, Some(header));

        // Only the valid provision should emit ProvisionAccepted
        let accepted_count = actions
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    Action::Continuation(ProtocolEvent::ProvisionAccepted { .. })
                )
            })
            .count();
        assert_eq!(accepted_count, 1);

        assert!(coordinator.has_any_verified_provisions(&Hash::from_bytes(b"tx_ok")));
        assert!(!coordinator.has_any_verified_provisions(&Hash::from_bytes(b"tx_bad")));
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

    // ═══════════════════════════════════════════════════════════════════════
    // Expected Provision Tracking (Fallback Detection) Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a CommittedBlockHeader that claims provisions target the given shards.
    fn make_committed_header_with_targets(
        shard: ShardGroupId,
        height: u64,
        provision_targets: Vec<ShardGroupId>,
    ) -> CommittedBlockHeader {
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
            provision_targets,
        };
        let header_hash = header.hash();
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = header_hash;
        qc.shard_group_id = shard;
        CommittedBlockHeader { header, qc }
    }

    /// Make a minimal Block at the given height for on_block_committed calls.
    fn make_block(height: u64) -> hyperscale_types::Block {
        hyperscale_types::Block::genesis(ShardGroupId(0), ValidatorId(0), Hash::ZERO, 0)
            .tap_mut(|b| b.header.height = BlockHeight(height))
    }

    /// Helper trait to mutate in-place and return self.
    trait TapMut {
        fn tap_mut(self, f: impl FnOnce(&mut Self)) -> Self;
    }
    impl<T> TapMut for T {
        fn tap_mut(mut self, f: impl FnOnce(&mut Self)) -> Self {
            f(&mut self);
            self
        }
    }

    #[test]
    fn test_expected_provision_tracked_when_header_targets_local_shard() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        // Remote shard 1 block targets shard 0 (our shard)
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_remote_block_committed(header, ValidatorId(3));

        // Should have one expected provision
        assert_eq!(coordinator.expected_provisions.len(), 1);
    }

    #[test]
    fn test_expected_provision_not_tracked_when_header_does_not_target_local_shard() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        // Remote shard 1 block targets shard 2 (NOT our shard)
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(2)]);
        coordinator.on_remote_block_committed(header, ValidatorId(3));

        assert_eq!(coordinator.expected_provisions.len(), 0);
    }

    #[test]
    fn test_expected_provision_cleared_on_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let source_shard = ShardGroupId(1);
        let header = make_committed_header_with_targets(source_shard, 10, vec![ShardGroupId(0)]);
        coordinator.on_remote_block_committed(header.clone(), ValidatorId(3));
        assert_eq!(coordinator.expected_provisions.len(), 1);

        // Provision arrives and is verified
        let provision = make_provision(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(vec![provision.clone()]);
        let result = make_verified_result(provision, true);
        coordinator.on_state_provisions_verified(vec![result], Some(header));

        // Expected provision should be cleared
        assert_eq!(coordinator.expected_provisions.len(), 0);
    }

    #[test]
    fn test_timeout_emits_request_missing_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        // Remote header arrives targeting our shard at local height 0
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_remote_block_committed(header, ValidatorId(3));

        // Advance blocks — should not emit before the timeout threshold
        for h in 1..=9 {
            let block = make_block(h);
            let actions = coordinator.on_block_committed(&block);
            assert!(actions.is_empty(), "Should not emit request at height {h}");
        }

        // At height 10, age = 10 - 0 = 10 >= PROVISION_FALLBACK_TIMEOUT_BLOCKS → fires
        let block = make_block(10);
        let actions = coordinator.on_block_committed(&block);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::RequestMissingProvisions {
                source_shard,
                block_height,
                proposer,
            } if *source_shard == ShardGroupId(1)
                && *block_height == BlockHeight(10)
                && *proposer == ValidatorId(0)
        ));
    }

    #[test]
    fn test_retry_throttled() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_remote_block_committed(header, ValidatorId(3));

        // Advance past timeout to trigger first request at height 10
        // (discovered_at=0, age=10 >= 10 → fires, last_requested_at=10)
        for h in 1..=10 {
            coordinator.on_block_committed(&make_block(h));
        }

        // Heights 11..=19 should be throttled (since_last = 1..9, all < 10)
        for h in 11..=19 {
            let actions = coordinator.on_block_committed(&make_block(h));
            assert!(actions.is_empty(), "Should throttle retry at height {h}");
        }

        // At height 20, retry should trigger (since_last = 20 - 10 = 10 >= 10)
        let actions = coordinator.on_block_committed(&make_block(20));
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::RequestMissingProvisions { .. }
        ));
    }

    #[test]
    fn test_no_timeout_when_provision_verified_in_time() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new(ShardGroupId(0), topology);

        let source_shard = ShardGroupId(1);
        let header = make_committed_header_with_targets(source_shard, 10, vec![ShardGroupId(0)]);
        coordinator.on_remote_block_committed(header.clone(), ValidatorId(3));

        // Advance a few blocks
        for h in 1..=5 {
            coordinator.on_block_committed(&make_block(h));
        }

        // Provision arrives and is verified before timeout
        let provision = make_provision(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(vec![provision.clone()]);
        let result = make_verified_result(provision, true);
        coordinator.on_state_provisions_verified(vec![result], Some(header));

        // Continue past timeout threshold
        for h in 6..=15 {
            let actions = coordinator.on_block_committed(&make_block(h));
            assert!(
                actions.is_empty(),
                "Should not request at height {h} (provision already verified)"
            );
        }
    }
}
