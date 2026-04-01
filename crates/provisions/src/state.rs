//! ProvisionCoordinator sub-state machine for centralized provision management.
//!
//! This module implements the provision coordination system that tracks all
//! cross-shard provisions, manages QC + merkle proof verification, and emits
//! verification events for downstream consumers.
//!
//! ## Provision Flow
//!
//! The source shard proposer broadcasts a `StateProvision` batch containing JVT
//! inclusion proofs. The target shard joins with remote block headers, then
//! dispatches `VerifyStateProvisions` to verify the QC signature once and
//! merkle proofs per provision against the committed state root.

use hyperscale_core::{Action, ProtocolEvent, ProvisionedTransaction};
use hyperscale_types::{
    BlockHeight, CommittedBlockHeader, Hash, NodeId, ProvisionBatch, ShardGroupId, StateProvision,
    TopologySnapshot, ValidatorId,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// Number of local committed blocks to wait before requesting missing provisions.
/// This gives the source shard proposer time to send provisions normally.
const PROVISION_FALLBACK_TIMEOUT_BLOCKS: u64 = 10;

/// Provision coordinator memory statistics for monitoring collection sizes.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProvisionMemoryStats {
    pub registered_txs: usize,
    pub verified_remote_headers: usize,
    pub pending_provisions: usize,
    pub verified_batches: usize,
    pub expected_provisions: usize,
}

/// Tracks an expected provision that hasn't arrived yet.
///
/// Created when a remote block header's `waves` field targets our shard.
/// Emits a single `RequestMissingProvisions` after the timeout; the fetch
/// protocol owns retries from that point.
#[derive(Debug, Clone)]
struct ExpectedProvision {
    discovered_at: BlockHeight,
    requested: bool,
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
    // Transaction Registration
    // ═══════════════════════════════════════════════════════════════════
    /// Registered cross-shard transactions we're tracking.
    /// Maps tx_hash -> registration info (required shards, etc.)
    registered_txs: HashMap<Hash, TxRegistration>,

    // ═══════════════════════════════════════════════════════════════════
    // Verified Remote Block Headers
    // ═══════════════════════════════════════════════════════════════════
    /// Verified committed block headers from remote shards.
    ///
    /// Populated exclusively via `on_verified_remote_header()` from the
    /// `RemoteHeaderCoordinator`. All headers here have passed QC verification.
    /// Used to join with provision batches for verkle proof verification.
    verified_remote_headers: HashMap<(ShardGroupId, BlockHeight), Arc<CommittedBlockHeader>>,

    // ═══════════════════════════════════════════════════════════════════
    // Verified Provisions
    // ═══════════════════════════════════════════════════════════════════
    /// Provision batches waiting for their corresponding remote block header.
    /// Keyed by (source_shard, block_height) since that's how we match to headers.
    pending_provisions: HashMap<(ShardGroupId, BlockHeight), Vec<ProvisionBatch>>,

    /// Verified provision batches keyed by (source_shard, block_height).
    /// Stored whole after proof verification — no per-tx decomposition.
    verified_batches: HashMap<(ShardGroupId, BlockHeight), ProvisionBatch>,

    // ═══════════════════════════════════════════════════════════════════
    // Expected Provision Tracking (fallback detection)
    // ═══════════════════════════════════════════════════════════════════
    /// Current local committed height (updated on each block commit).
    local_committed_height: BlockHeight,

    /// Expected provisions that haven't arrived yet.
    /// Keyed by `(source_shard, block_height)`. Populated when a remote
    /// header's `waves` field targets our shard. Cleared when
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
            .field("registered_txs", &self.registered_txs.len())
            .field(
                "verified_remote_headers",
                &self.verified_remote_headers.len(),
            )
            .finish()
    }
}

impl Default for ProvisionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvisionCoordinator {
    /// Create a new ProvisionCoordinator.
    pub fn new() -> Self {
        Self {
            registered_txs: HashMap::new(),
            verified_remote_headers: HashMap::new(),
            pending_provisions: HashMap::new(),
            verified_batches: HashMap::new(),
            local_committed_height: BlockHeight(0),
            expected_provisions: HashMap::new(),
            now: Duration::ZERO,
        }
    }

    /// Get provision coordinator memory statistics for monitoring collection sizes.
    pub fn memory_stats(&self) -> ProvisionMemoryStats {
        ProvisionMemoryStats {
            registered_txs: self.registered_txs.len(),
            verified_remote_headers: self.verified_remote_headers.len(),
            pending_provisions: self.pending_provisions.len(),
            verified_batches: self.verified_batches.len(),
            expected_provisions: self.expected_provisions.len(),
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

    /// Handle block committed - cleanup completed/aborted transactions and
    /// check for timed-out expected provisions.
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        block: &hyperscale_types::Block,
    ) -> Vec<Action> {
        // Clean up completed/aborted transactions (certificates committed).
        // All terminal states flow through TC commit — abort intents are NOT
        // terminal (they feed the execution accumulator). The TC with
        // decision=Aborted is the actual terminal event.
        for cert in &block.certificates {
            self.cleanup_tx(&cert.transaction_hash);
        }

        // Update local committed height
        self.local_committed_height = block.header.height;

        // Check for timed-out expected provisions and emit fallback requests
        let mut actions = vec![];
        let current_height = self.local_committed_height.0;

        for (&(source_shard, block_height), expected) in self.expected_provisions.iter_mut() {
            if expected.requested {
                continue;
            }

            let age = current_height.saturating_sub(expected.discovered_at.0);
            if age < PROVISION_FALLBACK_TIMEOUT_BLOCKS {
                continue;
            }

            warn!(
                source_shard = source_shard.0,
                block_height = block_height.0,
                age_blocks = age,
                "Provision timeout — requesting missing provisions via fallback"
            );

            expected.requested = true;
            actions.push(Action::RequestMissingProvisions {
                source_shard,
                block_height,
                proposer: expected.proposer,
                peers: topology.committee_for_shard(source_shard).to_vec(),
            });
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Remote Block Header Tracking
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a verified remote header from the RemoteHeaderCoordinator.
    ///
    /// Called when `RemoteHeaderVerified` is received. The header has already
    /// passed QC verification, so we store it directly as verified and:
    /// 1. Register expected provisions if waves target our shard
    /// 2. Join with any buffered provision batches waiting for this header
    pub fn on_verified_remote_header(
        &mut self,
        topology: &TopologySnapshot,
        committed_header: Arc<CommittedBlockHeader>,
    ) -> Vec<Action> {
        let shard = committed_header.shard_group_id();
        let height = committed_header.height();
        let key = (shard, height);

        // Ignore headers from our own shard.
        if shard == topology.local_shard() {
            return vec![];
        }

        // Only store headers that target our shard (i.e., we expect provisions).
        let local_shard = topology.local_shard();
        let targets_us = committed_header
            .header
            .waves
            .iter()
            .any(|w| w.0.contains(&local_shard));

        if targets_us {
            // Store as verified (QC already checked by coordinator).
            self.verified_remote_headers
                .insert(key, Arc::clone(&committed_header));

            let proposer = committed_header.header.proposer;
            self.expected_provisions.entry(key).or_insert_with(|| {
                debug!(
                    shard = shard.0,
                    height = height.0,
                    proposer = proposer.0,
                    "Tracking expected provision (verified remote block targets our shard)"
                );
                ExpectedProvision {
                    discovered_at: self.local_committed_height,
                    requested: false,
                    proposer,
                }
            });
        }

        // Join with buffered provision batches waiting for this header.
        let mut actions = vec![];
        if let Some(batches) = self.pending_provisions.remove(&key) {
            debug!(
                shard = shard.0,
                height = height.0,
                pending_count = batches.len(),
                "Found buffered provision batches for verified header"
            );
            for batch in batches {
                actions.extend(self.emit_provision_verification(
                    batch,
                    vec![committed_header.clone()],
                    topology,
                ));
            }
        }

        actions
    }

    // ═══════════════════════════════════════════════════════════════════════
    // State Provision Lifecycle
    // ═══════════════════════════════════════════════════════════════════════

    /// Handle a provision batch received from a source shard proposer.
    ///
    /// All transactions in a batch share the same `(source_shard, block_height)`
    /// via the batch's proof.
    /// Joins with the corresponding verified remote block header:
    /// - If a verified header exists: emit verification with single candidate
    /// - If no header yet: buffer the batch until `on_verified_remote_header` delivers it
    pub fn on_state_provisions_received(
        &mut self,
        topology: &TopologySnapshot,
        batch: ProvisionBatch,
    ) -> Vec<Action> {
        if batch.transactions.is_empty() {
            return vec![];
        }

        let source_shard = batch.source_shard;
        let block_height = batch.block_height;

        debug!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            count = batch.transactions.len(),
            "Provision batch received"
        );

        // Ignore provisions from our own shard
        if source_shard == topology.local_shard() {
            return vec![];
        }

        // Auto-register unknown txs for cycle detection
        for tx_entries in &batch.transactions {
            let tx_hash = tx_entries.tx_hash;
            self.registered_txs.entry(tx_hash).or_insert_with(|| {
                let mut required_shards = BTreeSet::new();
                required_shards.insert(source_shard);
                TxRegistration {
                    required_shards,
                    registered_at: BlockHeight(0),
                }
            });
        }

        // Look for matching verified remote header (pre-verified by RemoteHeaderCoordinator).
        let key = (source_shard, block_height);
        if let Some(verified_header) = self.verified_remote_headers.get(&key).cloned() {
            return self.emit_provision_verification(batch, vec![verified_header], topology);
        }

        // No verified header yet — buffer the batch
        debug!(
            source_shard = source_shard.0,
            block_height = block_height.0,
            count = batch.transactions.len(),
            "Buffering provision batch (waiting for remote header)"
        );
        self.pending_provisions.entry(key).or_default().push(batch);
        vec![]
    }

    /// Emit a `VerifyProvisionBatch` action for async batch verification.
    ///
    /// The QC is verified once across candidates; verkle proofs are checked
    /// against the verified header's state root.
    fn emit_provision_verification(
        &self,
        batch: ProvisionBatch,
        committed_headers: Vec<Arc<CommittedBlockHeader>>,
        topology: &TopologySnapshot,
    ) -> Vec<Action> {
        let source_shard = batch.source_shard;

        // Resolve ALL committee public keys in order for QC verification.
        // verify_qc_signature filters internally by the signer bitfield,
        // so it needs the full committee array (matching BFT's collect_qc_signer_keys).
        let committee = topology.committee_for_shard(source_shard);
        let committee_public_keys: Vec<_> = committee
            .iter()
            .map(|&validator_id| {
                topology
                    .public_key(validator_id)
                    .expect("committee member must have a public key")
            })
            .collect();

        // Per-validator voting power (parallel to committee_public_keys).
        // The action handler computes total_voting_power per-candidate from QC signer indices.
        let committee_voting_power: Vec<u64> = committee
            .iter()
            .map(|&validator_id| topology.voting_power(validator_id).unwrap_or(0))
            .collect();

        let quorum_threshold = topology.quorum_threshold_for_shard(source_shard);

        vec![Action::VerifyProvisionBatch {
            batch,
            committed_headers,
            committee_public_keys,
            committee_voting_power,
            quorum_threshold,
        }]
    }

    /// Handle batch-level provision verification result.
    ///
    /// If valid: store per-tx entries, emit events.
    /// Uses the verified header returned by the action handler directly (no re-lookup).
    pub fn on_state_provisions_verified(
        &mut self,
        _topology: &TopologySnapshot,
        batch: ProvisionBatch,
        committed_header: Option<Arc<CommittedBlockHeader>>,
        valid: bool,
    ) -> Vec<Action> {
        let mut actions = vec![];
        let source_shard = batch.source_shard;

        // Promote the verified header if we have one
        if let Some(ref header) = committed_header {
            let shard = header.header.shard_group_id;
            let height = header.header.height;
            let key = (shard, height);

            // Header already in verified_remote_headers from coordinator.
            // Ensure it's there (idempotent insert).
            self.verified_remote_headers
                .entry(key)
                .or_insert_with(|| header.clone());

            // Clear expected provision tracking — provisions arrived and verified.
            // Cancel any in-flight fallback fetch to prevent duplicate delivery.
            if self.expected_provisions.remove(&key).is_some() {
                actions.push(Action::CancelProvisionFetch {
                    source_shard: shard,
                    block_height: height,
                });
            }
        }

        if !valid {
            warn!(
                source_shard = source_shard.0,
                tx_count = batch.transactions.len(),
                "Provision batch verification failed"
            );
            return actions;
        }

        let Some(ref header) = committed_header else {
            warn!(
                source_shard = source_shard.0,
                "Provision batch marked valid but no committed header"
            );
            return actions;
        };

        // Store the verified batch whole
        let batch_key = (source_shard, batch.block_height);
        self.verified_batches.insert(batch_key, batch.clone());

        // Emit batch-level accepted event (used by livelock for cycle detection).
        actions.push(Action::Continuation(ProtocolEvent::ProvisionsAccepted {
            batch: batch.clone(),
        }));

        // Collect any transactions that are now fully provisioned across all shards.
        let mut completed = Vec::new();
        for tx_entries in &batch.transactions {
            let tx_hash = tx_entries.tx_hash;

            debug!(
                tx_hash = %tx_hash,
                source_shard = source_shard.0,
                entries = tx_entries.entries.len(),
                "State provision verified successfully"
            );

            // Check if ALL required shards have verified provisions
            if self.all_shards_verified(tx_hash) {
                let all_provisions = self.collect_provisions_for_tx(
                    tx_hash,
                    _topology.local_shard(),
                    header.header.timestamp,
                );

                debug!(
                    tx_hash = %tx_hash,
                    "All shards verified - ready for execution"
                );

                completed.push(ProvisionedTransaction {
                    tx_hash,
                    provisions: all_provisions,
                });
            }
        }
        if !completed.is_empty() {
            actions.push(Action::Continuation(ProtocolEvent::ProvisioningComplete {
                transactions: completed,
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
        self.verified_batches
            .values()
            .any(|b| b.transactions.iter().any(|tx| tx.tx_hash == *tx_hash))
    }

    /// Get all tx_hashes with verified provisions from a specific shard.
    pub fn txs_with_provisions_from(&self, shard: ShardGroupId) -> Option<HashSet<Hash>> {
        let txs: HashSet<Hash> = self
            .verified_batches
            .iter()
            .filter(|(&(s, _), _)| s == shard)
            .flat_map(|(_, b)| b.transactions.iter().map(|tx| tx.tx_hash))
            .collect();
        if txs.is_empty() {
            None
        } else {
            Some(txs)
        }
    }

    /// Get the nodes contained in verified provisions for a tx from a specific shard.
    ///
    /// Used by livelock to check for actual node-level overlap.
    pub fn provision_nodes(&self, tx_hash: Hash, shard: ShardGroupId) -> HashSet<NodeId> {
        for (&(s, _), batch) in &self.verified_batches {
            if s != shard {
                continue;
            }
            for tx in &batch.transactions {
                if tx.tx_hash == tx_hash {
                    return tx.entries.iter().filter_map(|e| e.node_id()).collect();
                }
            }
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

    /// Look up a verified remote committed block header by shard and height.
    pub fn get_remote_header(
        &self,
        shard: ShardGroupId,
        height: BlockHeight,
    ) -> Option<&Arc<CommittedBlockHeader>> {
        self.verified_remote_headers.get(&(shard, height))
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

        registration.required_shards.iter().all(|&shard| {
            self.verified_batches.iter().any(|(&(s, _), b)| {
                s == shard && b.transactions.iter().any(|tx| tx.tx_hash == tx_hash)
            })
        })
    }

    /// Collect all verified provisions for a transaction across shards.
    fn collect_provisions_for_tx(
        &self,
        tx_hash: Hash,
        local_shard: ShardGroupId,
        block_timestamp: u64,
    ) -> Vec<StateProvision> {
        self.verified_batches
            .iter()
            .flat_map(|(&(source_shard, block_height), batch)| {
                batch
                    .transactions
                    .iter()
                    .filter(move |tx| tx.tx_hash == tx_hash)
                    .map(move |tx| StateProvision {
                        transaction_hash: tx_hash,
                        target_shard: local_shard,
                        source_shard,
                        block_height,
                        block_timestamp,
                        entries: Arc::new(tx.entries.clone()),
                    })
            })
            .collect()
    }

    /// Clean up all state for a transaction.
    ///
    /// Removes the registration and prunes verified_batches where no
    /// transactions remain registered. Orphaned verified_remote_headers
    /// (no batch, pending provisions, or expected provisions) are also removed.
    fn cleanup_tx(&mut self, tx_hash: &Hash) {
        if self.registered_txs.remove(tx_hash).is_none() {
            return;
        }

        // Prune verified_batches where no transactions are still registered.
        let pruned_keys: Vec<_> = self
            .verified_batches
            .iter()
            .filter(|(_, batch)| {
                !batch
                    .transactions
                    .iter()
                    .any(|tx| self.registered_txs.contains_key(&tx.tx_hash))
            })
            .map(|(&key, _)| key)
            .collect();

        for key in &pruned_keys {
            self.verified_batches.remove(key);
        }

        // Prune verified_remote_headers with no corresponding batch,
        // pending provisions, or expected provisions.
        self.verified_remote_headers.retain(|key, _| {
            self.verified_batches.contains_key(key)
                || self.pending_provisions.contains_key(key)
                || self.expected_provisions.contains_key(key)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        bls_keypair_from_seed, BlockHeader, Bls12381G1PrivateKey, QuorumCertificate,
        SubstateInclusionProof, TopologySnapshot, TxEntries, ValidatorInfo, ValidatorSet, WaveId,
    };

    fn make_test_topology(local_shard: ShardGroupId) -> TopologySnapshot {
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

        TopologySnapshot::with_local_shard(
            ValidatorId(local_shard.0 * 3), // First validator in shard
            local_shard,
            2,
            ValidatorSet::new(validators),
        )
    }

    fn make_registration(required_shards: Vec<ShardGroupId>) -> TxRegistration {
        TxRegistration {
            required_shards: required_shards.into_iter().collect(),
            registered_at: BlockHeight(1),
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup Tests
    // ═══════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════
    // Remote Block Header Tracking Tests (Unverified Buffer)
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a CommittedBlockHeader with waves targeting ShardGroupId(0)
    /// (the local shard in most tests) so it gets stored in verified_remote_headers.
    fn make_committed_header(shard: ShardGroupId, height: u64) -> Arc<CommittedBlockHeader> {
        make_committed_header_with_targets(shard, height, vec![ShardGroupId(0)])
    }

    #[test]
    fn test_remote_header_stored_in_verified_buffer() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header(ShardGroupId(1), 10);
        let actions = coordinator.on_verified_remote_header(&topology, header);
        assert!(actions.is_empty());

        // Should be in verified buffer (pre-verified by RemoteHeaderCoordinator)
        assert_eq!(coordinator.verified_remote_header_count(), 1);
        assert!(coordinator
            .get_remote_header(ShardGroupId(1), BlockHeight(10))
            .is_some());
    }

    #[test]
    fn test_remote_header_from_own_shard_ignored() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header(ShardGroupId(0), 10);
        coordinator.on_verified_remote_header(&topology, header);

        assert_eq!(coordinator.verified_remote_header_count(), 0);
    }

    #[test]
    fn test_remote_header_multiple_shards_and_heights() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let _sender = ValidatorId(3);
        coordinator
            .on_verified_remote_header(&topology, make_committed_header(ShardGroupId(1), 10));
        coordinator
            .on_verified_remote_header(&topology, make_committed_header(ShardGroupId(1), 11));
        // Use a different sender for shard 2 (since our topology has different validators per shard)
        coordinator
            .on_verified_remote_header(&topology, make_committed_header(ShardGroupId(2), 10));

        assert_eq!(coordinator.verified_remote_header_count(), 3);
    }

    #[test]
    fn test_remote_header_same_shard_height_overwrites() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header1 = make_committed_header(ShardGroupId(1), 10);
        let header2 = make_committed_header(ShardGroupId(1), 10);

        // Two verified headers for same (shard, height) — last wins
        coordinator.on_verified_remote_header(&topology, header1);
        coordinator.on_verified_remote_header(&topology, header2);

        // Only one entry per (shard, height) in verified map
        assert_eq!(coordinator.verified_remote_header_count(), 1);
    }

    #[test]
    fn test_remote_header_same_shard_height_same_validator_overwrites() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let _sender = ValidatorId(3);
        coordinator
            .on_verified_remote_header(&topology, make_committed_header(ShardGroupId(1), 10));
        coordinator
            .on_verified_remote_header(&topology, make_committed_header(ShardGroupId(1), 10));

        // Same (shard, height, sender) — should overwrite, not duplicate
        assert_eq!(coordinator.verified_remote_header_count(), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Provision Lifecycle Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a ProvisionBatch for testing with a single transaction.
    fn make_batch(
        tx_hash: Hash,
        source_shard: ShardGroupId,
        _target_shard: ShardGroupId,
        height: u64,
    ) -> ProvisionBatch {
        make_batch_multi(vec![tx_hash], source_shard, height)
    }

    /// Build a ProvisionBatch for testing with multiple transactions.
    fn make_batch_multi(
        tx_hashes: Vec<Hash>,
        source_shard: ShardGroupId,
        height: u64,
    ) -> ProvisionBatch {
        let transactions = tx_hashes
            .into_iter()
            .map(|tx_hash| TxEntries {
                tx_hash,
                entries: vec![],
            })
            .collect();
        ProvisionBatch {
            source_shard,
            block_height: BlockHeight(height),
            proof: SubstateInclusionProof::dummy(),
            transactions,
        }
    }

    #[test]
    fn test_provision_received_with_header_emits_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // First: header arrives
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header);

        // Then: batch arrives — should emit VerifyProvisionBatch
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvisionBatch { batch, .. } if batch.transactions[0].tx_hash == tx_hash
        ));

        // Should auto-register the tx
        assert!(coordinator.is_registered(&tx_hash));
    }

    #[test]
    fn test_provision_received_without_header_buffers() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Batch arrives before header — should buffer
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert!(actions.is_empty());
        // Should still auto-register
        assert!(coordinator.is_registered(&tx_hash));
    }

    #[test]
    fn test_header_arrival_triggers_buffered_provision_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Batch arrives first — buffered
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch);

        // Then header arrives — should trigger verification of buffered batch
        let header = make_committed_header(source_shard, 10);
        let actions = coordinator.on_verified_remote_header(&topology, header);

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::VerifyProvisionBatch { batch, .. } if batch.transactions[0].tx_hash == tx_hash
        ));
    }

    #[test]
    fn test_provision_from_own_shard_ignored() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let batch = make_batch(
            Hash::from_bytes(b"tx1"),
            ShardGroupId(0), // own shard
            ShardGroupId(1),
            10,
        );
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert!(actions.is_empty());
        // Should NOT auto-register
        assert!(!coordinator.is_registered(&Hash::from_bytes(b"tx1")));
    }

    #[test]
    fn test_duplicate_provision_ignored_after_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Setup: header + batch + verification
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());

        // Simulate successful verification
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Second batch for same (tx, shard) goes through verification again
        // (proof must be verified as a whole — no per-tx pre-filtering).
        // Duplicate entries are harmlessly re-inserted by on_state_provisions_verified.
        let batch2 = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch2);
        assert!(actions
            .iter()
            .any(|a| matches!(a, Action::VerifyProvisionBatch { .. })));
    }

    #[test]
    fn test_provision_verified_stores_entries() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Setup
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());

        // Verify
        let actions =
            coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Should emit ProvisionsAccepted with the batch
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsAccepted { .. })
        )));

        // Should have verified provisions
        assert!(coordinator.has_any_verified_provisions(&tx_hash));
    }

    #[test]
    fn test_provision_verified_invalid_does_not_store() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header);
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());

        // Verification fails — no committed_header returned
        let actions = coordinator.on_state_provisions_verified(&topology, batch, None, false);

        assert!(actions.iter().all(|a| !matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisionsAccepted { .. })
        )));
        assert!(!coordinator.has_any_verified_provisions(&tx_hash));
    }

    #[test]
    fn test_all_shards_verified_emits_provisioning_complete() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let shard1 = ShardGroupId(1);
        let shard2 = ShardGroupId(2);

        // Register tx requiring provisions from two shards
        let registration = make_registration(vec![shard1, shard2]);
        coordinator.on_tx_registered(tx_hash, registration);

        // Verify first shard
        let header1 = make_committed_header(shard1, 10);
        coordinator.on_verified_remote_header(&topology, header1.clone());
        let batch1 = make_batch(tx_hash, shard1, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch1.clone());
        let actions =
            coordinator.on_state_provisions_verified(&topology, batch1, Some(header1), true);

        // Should NOT emit ProvisioningComplete yet (shard2 still pending)
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisioningComplete { .. })
        )));

        // Verify second shard
        let header2 = make_committed_header(shard2, 10);
        coordinator.on_verified_remote_header(&topology, header2.clone());
        let batch2 = make_batch(tx_hash, shard2, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch2.clone());
        let actions =
            coordinator.on_state_provisions_verified(&topology, batch2, Some(header2), true);

        // NOW should emit ProvisioningComplete
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Continuation(ProtocolEvent::ProvisioningComplete { transactions })
            if transactions.iter().any(|pt| pt.tx_hash == tx_hash)
        )));
    }

    #[test]
    fn test_provision_nodes_returns_node_ids() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Create a batch with entries that have valid node IDs
        let mut storage_key = Vec::with_capacity(20 + 30 + 1 + 1);
        storage_key.extend_from_slice(&[0u8; 20]);
        storage_key.extend_from_slice(&[42u8; 30]); // node_id
        storage_key.push(0); // partition
        storage_key.push(0); // sort_key

        let entry = hyperscale_types::StateEntry::new(storage_key, Some(vec![1, 2, 3]));
        let batch = ProvisionBatch {
            source_shard,
            block_height: BlockHeight(10),
            proof: SubstateInclusionProof::dummy(),
            transactions: vec![TxEntries {
                tx_hash,
                entries: vec![entry],
            }],
        };

        // Setup + verify
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Check node extraction
        let nodes = coordinator.provision_nodes(tx_hash, source_shard);
        assert_eq!(nodes.len(), 1);
        assert!(nodes.contains(&NodeId([42u8; 30])));
    }

    #[test]
    fn test_txs_with_provisions_from_tracks_reverse_index() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Before verification
        assert!(coordinator.txs_with_provisions_from(source_shard).is_none());

        // Setup + verify
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // After verification
        let txs = coordinator.txs_with_provisions_from(source_shard).unwrap();
        assert!(txs.contains(&tx_hash));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch Verification Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_provision_batch_emits_single_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header);

        // Send batch with 3 transactions from the same block
        let tx_hashes: Vec<_> = (0..3)
            .map(|i| Hash::from_bytes(format!("tx{i}").as_bytes()))
            .collect();
        let batch = make_batch_multi(tx_hashes, source_shard, 10);

        let actions = coordinator.on_state_provisions_received(&topology, batch);

        // Should emit exactly ONE VerifyProvisionBatch action with all 3 transactions
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::VerifyProvisionBatch { batch, .. } => {
                assert_eq!(batch.transactions.len(), 3);
            }
            other => panic!("Expected VerifyProvisionBatch, got {:?}", other),
        }
    }

    #[test]
    fn test_provision_uses_single_verified_candidate() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);

        // Verified header from coordinator
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header);
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Batch arrives — should send single verified candidate
        let batch = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch);

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::VerifyProvisionBatch {
                committed_headers, ..
            } => {
                assert_eq!(committed_headers.len(), 1);
            }
            other => panic!("Expected VerifyProvisionBatch, got {:?}", other),
        }
    }

    #[test]
    fn test_provision_uses_verified_header_when_available() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());

        // First batch verifies (promotes header to verified)
        let batch1 = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch1.clone());
        coordinator.on_state_provisions_verified(&topology, batch1, Some(header.clone()), true);

        // Second batch for different tx at same (shard, height)
        let batch2 = make_batch(Hash::from_bytes(b"tx2"), source_shard, ShardGroupId(0), 10);
        let actions = coordinator.on_state_provisions_received(&topology, batch2);

        // Should send only the verified header (single candidate)
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::VerifyProvisionBatch {
                committed_headers, ..
            } => {
                assert_eq!(committed_headers.len(), 1);
            }
            other => panic!("Expected VerifyProvisionBatch, got {:?}", other),
        }
    }

    #[test]
    fn test_batch_invalid_does_not_store_any() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());

        let batch = make_batch_multi(
            vec![Hash::from_bytes(b"tx_ok"), Hash::from_bytes(b"tx_bad")],
            source_shard,
            10,
        );

        coordinator.on_state_provisions_received(&topology, batch.clone());

        // Entire batch fails verification
        let actions =
            coordinator.on_state_provisions_verified(&topology, batch, Some(header), false);

        // No ProvisionsAccepted should be emitted
        let accepted_count = actions
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    Action::Continuation(ProtocolEvent::ProvisionsAccepted { .. })
                )
            })
            .count();
        assert_eq!(accepted_count, 0);

        assert!(!coordinator.has_any_verified_provisions(&Hash::from_bytes(b"tx_ok")));
        assert!(!coordinator.has_any_verified_provisions(&Hash::from_bytes(b"tx_bad")));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Unverified Buffer Tests
    // ═══════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════
    // Expected Provision Tracking (Fallback Detection) Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Build a CommittedBlockHeader that claims provisions target the given shards.
    fn make_committed_header_with_targets(
        shard: ShardGroupId,
        height: u64,
        provision_targets: Vec<ShardGroupId>,
    ) -> Arc<CommittedBlockHeader> {
        // Convert flat provision targets into waves: each target shard becomes
        // its own single-dependency wave. This preserves the test semantics
        // (provision_targets() returns the same set).
        let waves: Vec<WaveId> = provision_targets
            .into_iter()
            .map(|s| WaveId(std::collections::BTreeSet::from([s])))
            .collect();
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
            transaction_root: Hash::ZERO,
            receipt_root: Hash::ZERO,
            waves,
        };
        let header_hash = header.hash();
        let mut qc = QuorumCertificate::genesis();
        qc.block_hash = header_hash;
        qc.shard_group_id = shard;
        Arc::new(CommittedBlockHeader::new(header, qc))
    }

    /// Make a minimal Block at the given height for on_block_committed calls.
    fn make_block(height: u64) -> hyperscale_types::Block {
        hyperscale_types::Block::genesis(ShardGroupId(0), ValidatorId(0), Hash::ZERO)
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
        let mut coordinator = ProvisionCoordinator::new();

        // Remote shard 1 block targets shard 0 (our shard)
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);

        // Should have one expected provision
        assert_eq!(coordinator.expected_provisions.len(), 1);
    }

    #[test]
    fn test_expected_provision_not_tracked_when_header_does_not_target_local_shard() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Remote shard 1 block targets shard 2 (NOT our shard)
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(2)]);
        coordinator.on_verified_remote_header(&topology, header);

        // Header should NOT be stored (not expecting provisions from it)
        assert_eq!(coordinator.verified_remote_header_count(), 0);
        assert_eq!(coordinator.expected_provisions.len(), 0);
    }

    #[test]
    fn test_expected_provision_cleared_on_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let header = make_committed_header_with_targets(source_shard, 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header.clone());
        assert_eq!(coordinator.expected_provisions.len(), 1);

        // Batch arrives and is verified
        let batch = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Expected provision should be cleared
        assert_eq!(coordinator.expected_provisions.len(), 0);
    }

    #[test]
    fn test_timeout_emits_request_missing_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        // Remote header arrives targeting our shard at local height 0
        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);

        // Advance blocks — should not emit before the timeout threshold (10 blocks)
        for h in 1..=9 {
            let block = make_block(h);
            let actions = coordinator.on_block_committed(&topology, &block);
            assert!(actions.is_empty(), "Should not emit request at height {h}");
        }

        // At height 10, age = 10 - 0 = 10 >= PROVISION_FALLBACK_TIMEOUT_BLOCKS → fires
        let block = make_block(10);
        let actions = coordinator.on_block_committed(&topology, &block);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            Action::RequestMissingProvisions {
                source_shard,
                block_height,
                proposer,
                ..
            } if *source_shard == ShardGroupId(1)
                && *block_height == BlockHeight(10)
                && *proposer == ValidatorId(0)
        ));
    }

    #[test]
    fn test_no_re_emission_after_initial_request() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let header = make_committed_header_with_targets(ShardGroupId(1), 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header);

        // Advance past timeout to trigger the one-time request at height 30
        for h in 1..=30 {
            coordinator.on_block_committed(&topology, &make_block(h));
        }

        // Coordinator is fire-and-forget: no further emissions at any height.
        for h in 31..=100 {
            let actions = coordinator.on_block_committed(&topology, &make_block(h));
            assert!(
                actions.is_empty(),
                "Should never re-emit after initial request (height {h})"
            );
        }
    }

    #[test]
    fn test_no_timeout_when_provision_verified_in_time() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);
        let header = make_committed_header_with_targets(source_shard, 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header.clone());

        // Advance a few blocks
        for h in 1..=5 {
            coordinator.on_block_committed(&topology, &make_block(h));
        }

        // Batch arrives and is verified before timeout
        let batch = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Continue past timeout threshold
        for h in 6..=15 {
            let actions = coordinator.on_block_committed(&topology, &make_block(h));
            assert!(
                actions.is_empty(),
                "Should not request at height {h} (provision already verified)"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cleanup Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cleanup_removes_registration_and_prunes_batches() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        // Setup: header + batch + verification
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        assert!(coordinator.is_registered(&tx_hash));
        assert!(coordinator.has_any_verified_provisions(&tx_hash));
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Cleanup via block commit
        let mut block = make_block(1);
        block.certificates.push(std::sync::Arc::new(
            hyperscale_types::TransactionCertificate {
                transaction_hash: tx_hash,
                decision: hyperscale_types::TransactionDecision::Accept,
                shard_proofs: std::collections::BTreeMap::new(),
            },
        ));
        coordinator.on_block_committed(&topology, &block);

        // Registration, verified batch, and remote header all pruned
        assert!(!coordinator.is_registered(&tx_hash));
        assert!(!coordinator.has_any_verified_provisions(&tx_hash));
        assert_eq!(coordinator.verified_remote_header_count(), 0);
    }

    #[test]
    fn test_cleanup_preserves_batch_with_remaining_registered_tx() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");
        let source_shard = ShardGroupId(1);

        // Two txs in one batch
        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());
        let batch = make_batch_multi(vec![tx1, tx2], source_shard, 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        assert!(coordinator.has_any_verified_provisions(&tx1));
        assert!(coordinator.has_any_verified_provisions(&tx2));

        // Only commit tx1 — tx2 still registered
        let mut block = make_block(1);
        block.certificates.push(std::sync::Arc::new(
            hyperscale_types::TransactionCertificate {
                transaction_hash: tx1,
                decision: hyperscale_types::TransactionDecision::Accept,
                shard_proofs: std::collections::BTreeMap::new(),
            },
        ));
        coordinator.on_block_committed(&topology, &block);

        // Batch and header preserved because tx2 is still registered
        assert!(!coordinator.is_registered(&tx1));
        assert!(coordinator.is_registered(&tx2));
        assert!(coordinator.has_any_verified_provisions(&tx2));
        assert_eq!(coordinator.verified_remote_header_count(), 1);

        // Now commit tx2
        let mut block2 = make_block(2);
        block2.certificates.push(std::sync::Arc::new(
            hyperscale_types::TransactionCertificate {
                transaction_hash: tx2,
                decision: hyperscale_types::TransactionDecision::Accept,
                shard_proofs: std::collections::BTreeMap::new(),
            },
        ));
        coordinator.on_block_committed(&topology, &block2);

        // Now everything is pruned
        assert!(!coordinator.has_any_verified_provisions(&tx2));
        assert_eq!(coordinator.verified_remote_header_count(), 0);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CancelProvisionFetch Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verified_provisions_emit_cancel_fetch() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let source_shard = ShardGroupId(1);

        // Remote header targeting our shard — creates expected_provision entry
        let header = make_committed_header_with_targets(source_shard, 10, vec![ShardGroupId(0)]);
        coordinator.on_verified_remote_header(&topology, header.clone());
        assert_eq!(coordinator.expected_provisions.len(), 1);

        // Batch arrives and is verified
        let batch = make_batch(Hash::from_bytes(b"tx1"), source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        let actions =
            coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        // Should emit CancelProvisionFetch action
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::CancelProvisionFetch {
                    source_shard: s,
                    block_height: h,
                } if *s == source_shard && *h == BlockHeight(10)
            )),
            "Should emit CancelProvisionFetch when expected provision is verified"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Verified Batch Retention Tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_verified_batch_queryable_after_verification() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut coordinator = ProvisionCoordinator::new();

        let tx_hash = Hash::from_bytes(b"tx1");
        let source_shard = ShardGroupId(1);

        let header = make_committed_header(source_shard, 10);
        coordinator.on_verified_remote_header(&topology, header.clone());
        let batch = make_batch(tx_hash, source_shard, ShardGroupId(0), 10);
        coordinator.on_state_provisions_received(&topology, batch.clone());
        coordinator.on_state_provisions_verified(&topology, batch, Some(header), true);

        assert!(coordinator.txs_with_provisions_from(source_shard).is_some());
        let txs = coordinator.txs_with_provisions_from(source_shard).unwrap();
        assert!(txs.contains(&tx_hash));
    }
}
