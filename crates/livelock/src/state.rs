//! LivelockState sub-state machine for cycle detection and deferral management.
//!
//! This module implements the provision-based cycle detection system that
//! prevents bidirectional livelock in cross-shard transactions.

use crate::tracker::{CommittedCrossShardTracker, ProvisionTracker, RemoteStateNeeds};
use hyperscale_core::{Action, Event, SubStateMachine};
use hyperscale_types::{
    BlockHeight, CommitmentProof, CycleProof, DeferReason, Hash, NodeId, RoutableTransaction,
    ShardGroupId, Topology, TransactionDefer,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace};

/// Configuration for livelock prevention.
#[derive(Debug, Clone)]
pub struct LivelockConfig {
    /// How long to keep tombstones for deferred transactions.
    pub tombstone_ttl: Duration,
    /// Number of blocks before a stuck transaction times out.
    pub execution_timeout_blocks: u64,
    /// Maximum retry attempts before permanent abort.
    pub max_retries: u32,
}

impl Default for LivelockConfig {
    fn default() -> Self {
        Self {
            tombstone_ttl: Duration::from_secs(30),
            execution_timeout_blocks: 30,
            max_retries: 3,
        }
    }
}

/// Livelock prevention state machine.
///
/// Handles:
/// - Cycle detection (from provision signals)
/// - Deferral queuing for block inclusion
/// - Tombstones for late provision filtering
///
/// Does NOT handle:
/// - Retry creation (handled by MempoolState)
/// - Status updates (handled by MempoolState)
/// - Provision quorum tracking (handled by ExecutionState)
pub struct LivelockState {
    /// This node's shard group.
    local_shard: ShardGroupId,

    /// Network topology for shard lookups.
    topology: Arc<dyn Topology>,

    /// Tracks committed cross-shard TXs and which shards they need provisions from.
    committed_tracker: CommittedCrossShardTracker,

    /// Tracks provisions received: (tx_hash, source_shard) pairs.
    /// Used for both early detection and deduplication.
    provision_tracker: ProvisionTracker,

    /// Tombstones for deferred transactions to discard late-arriving provisions.
    /// Maps tx_hash -> tombstone expiry time.
    /// Added when deferral COMMITS (not when cycle detected).
    deferred_tombstones: HashMap<Hash, Duration>,

    /// Commitment proofs from remote transactions.
    /// Used to build CycleProof when deferring due to livelock cycle.
    /// Maps tx_hash -> CommitmentProof
    commitment_proofs: HashMap<Hash, CommitmentProof>,

    /// Deferrals ready to be included in next block proposal.
    /// Kept until they appear in a committed block.
    pending_deferrals: Vec<TransactionDefer>,

    /// Current time.
    now: Duration,

    /// Configuration.
    config: LivelockConfig,
}

impl std::fmt::Debug for LivelockState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LivelockState")
            .field("local_shard", &self.local_shard)
            .field("committed_tracker_len", &self.committed_tracker.len())
            .field("provision_tracker_len", &self.provision_tracker.len())
            .field("deferred_tombstones_len", &self.deferred_tombstones.len())
            .field("pending_deferrals_len", &self.pending_deferrals.len())
            .finish()
    }
}

impl LivelockState {
    /// Create a new LivelockState.
    pub fn new(local_shard: ShardGroupId, topology: Arc<dyn Topology>) -> Self {
        Self::with_config(local_shard, topology, LivelockConfig::default())
    }

    /// Create a new LivelockState with custom configuration.
    pub fn with_config(
        local_shard: ShardGroupId,
        topology: Arc<dyn Topology>,
        config: LivelockConfig,
    ) -> Self {
        Self {
            local_shard,
            topology,
            committed_tracker: CommittedCrossShardTracker::new(),
            provision_tracker: ProvisionTracker::new(),
            deferred_tombstones: HashMap::new(),
            commitment_proofs: HashMap::new(),
            pending_deferrals: Vec::new(),
            now: Duration::ZERO,
            config,
        }
    }

    /// Called when a cross-shard transaction is committed.
    ///
    /// Registers the transaction for cycle detection by tracking which
    /// shards and specific nodes it needs provisions from.
    pub fn on_cross_shard_committed(&mut self, tx: &RoutableTransaction, height: BlockHeight) {
        let tx_hash = tx.hash();

        // Determine which shards and nodes we need provisions from
        let needs = self.compute_remote_state_needs(tx);

        if needs.shards.is_empty() {
            // Not actually cross-shard, nothing to track
            return;
        }

        debug!(
            tx_hash = %tx_hash,
            height = height.0,
            shards = ?needs.shards,
            "Tracking committed cross-shard TX for cycle detection"
        );

        self.committed_tracker.add(tx_hash, needs);
    }

    /// Compute which remote shards and nodes a transaction needs provisions from.
    fn compute_remote_state_needs(&self, tx: &RoutableTransaction) -> RemoteStateNeeds {
        let local_shard = self.local_shard;

        // Collect all reads and writes, grouped by shard
        let mut nodes_by_shard: HashMap<ShardGroupId, HashSet<NodeId>> = HashMap::new();

        // Add read nodes (provisions come from read shards)
        for node_id in &tx.declared_reads {
            let shard = self.topology.shard_for_node_id(node_id);
            if shard != local_shard {
                nodes_by_shard.entry(shard).or_default().insert(*node_id);
            }
        }

        // Add write nodes from remote shards (for read-your-writes scenarios)
        for node_id in &tx.declared_writes {
            let shard = self.topology.shard_for_node_id(node_id);
            if shard != local_shard {
                nodes_by_shard.entry(shard).or_default().insert(*node_id);
            }
        }

        let shards = nodes_by_shard.keys().copied().collect();

        RemoteStateNeeds {
            shards,
            nodes_by_shard,
        }
    }

    /// Called when a quorum of verified provisions is reached for a source shard.
    ///
    /// This is the ONLY entry point for cycle detection in the new architecture.
    /// This method only processes provisions that
    /// have been signature-verified and have reached quorum threshold. This prevents
    /// Byzantine validators from triggering false deferrals with forged provisions.
    ///
    /// # Arguments
    /// * `remote_tx_hash` - The remote transaction's hash
    /// * `source_shard` - The shard that reached quorum
    /// * `commitment_proof` - The aggregated proof from the source shard
    pub fn on_provision_quorum_reached(
        &mut self,
        remote_tx_hash: Hash,
        source_shard: ShardGroupId,
        commitment_proof: &CommitmentProof,
    ) {
        trace!(
            remote_tx = %remote_tx_hash,
            source_shard = source_shard.0,
            signer_count = commitment_proof.signer_count(),
            "Processing verified quorum for cycle detection"
        );

        // Check tombstone - discard late provisions for deferred TXs
        if self.deferred_tombstones.contains_key(&remote_tx_hash) {
            trace!(
                remote_tx = %remote_tx_hash,
                "Discarding quorum - TX has tombstone (was deferred)"
            );
            return;
        }

        // Check if we've already processed this (tx, shard) for cycle detection
        if !self.provision_tracker.add(remote_tx_hash, source_shard) {
            return;
        }

        // Store the commitment proof for building CycleProof later
        self.commitment_proofs
            .insert(remote_tx_hash, commitment_proof.clone());

        // Get nodes from the commitment proof
        let remote_tx_nodes = commitment_proof.nodes();

        // Check for cycle with our local committed TXs
        self.check_for_cycle(remote_tx_hash, source_shard, &remote_tx_nodes);
    }

    /// Check for a bidirectional cycle with a remote transaction.
    ///
    /// A TRUE cycle exists when:
    /// 1. We have a local TX that needs provisions from source_shard for SPECIFIC NODES
    /// 2. The remote TX needs provisions from us for OVERLAPPING NODES
    ///
    /// If the nodes don't overlap, there's no actual deadlock risk - the transactions
    /// can proceed independently even though they cross the same shards.
    ///
    /// When a true cycle is detected, the transaction with the higher hash loses
    /// and is deferred. Both shards independently reach the same conclusion.
    fn check_for_cycle(
        &mut self,
        remote_tx_hash: Hash,
        source_shard: ShardGroupId,
        remote_tx_nodes: &HashSet<NodeId>,
    ) {
        // Get all our committed TXs that need provisions from the remote shard
        // Clone to avoid borrow issues when we need to call queue_deferral
        let local_txs_needing_source: Vec<Hash> = self
            .committed_tracker
            .txs_needing_shard(source_shard)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();

        if local_txs_needing_source.is_empty() {
            return;
        }

        // For each local TX that needs the source shard...
        for local_tx_hash in local_txs_needing_source {
            // Get the specific nodes our local TX needs from the remote shard
            let local_nodes_needed = match self
                .committed_tracker
                .nodes_needed_from_shard(&local_tx_hash, source_shard)
            {
                Some(nodes) => nodes,
                None => continue, // Shouldn't happen, but be safe
            };

            // Check if there's actual node-level overlap
            // A true cycle only exists if the remote TX's nodes overlap with our local TX's needs
            let has_overlap = local_nodes_needed
                .iter()
                .any(|node| remote_tx_nodes.contains(node));

            if !has_overlap {
                // No actual state conflict - these TXs can proceed independently
                trace!(
                    local_tx = %local_tx_hash,
                    remote_tx = %remote_tx_hash,
                    "No node overlap - skipping cycle detection"
                );
                continue;
            }

            // There IS a true bidirectional cycle with overlapping state!
            // Determine winner by hash comparison (lower hash wins)
            let (winner, loser) = if local_tx_hash < remote_tx_hash {
                (local_tx_hash, remote_tx_hash)
            } else if remote_tx_hash < local_tx_hash {
                (remote_tx_hash, local_tx_hash)
            } else {
                // Same hash - impossible in practice, skip
                continue;
            };

            // Only defer if we own the loser
            if loser == local_tx_hash {
                debug!(
                    local_tx = %local_tx_hash,
                    remote_tx = %remote_tx_hash,
                    winner = %winner,
                    "TRUE cycle detected with overlapping nodes - our TX loses, queuing deferral"
                );

                self.queue_deferral(local_tx_hash, winner);
            } else {
                debug!(
                    local_tx = %local_tx_hash,
                    remote_tx = %remote_tx_hash,
                    winner = %winner,
                    "Cycle detected - our TX wins, remote TX should defer"
                );
            }
        }
    }

    /// Queue a deferral for inclusion in the next block.
    fn queue_deferral(&mut self, loser_tx: Hash, winner_tx: Hash) {
        // Check if already queued
        if self.pending_deferrals.iter().any(|d| d.tx_hash == loser_tx) {
            trace!(tx = %loser_tx, "Deferral already queued");
            return;
        }

        // Build CycleProof from the stored commitment proof for the winner
        let proof = self
            .commitment_proofs
            .get(&winner_tx)
            .map(|commitment| CycleProof::new(winner_tx, commitment.clone()));

        let deferral = TransactionDefer {
            tx_hash: loser_tx,
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: winner_tx,
            },
            block_height: BlockHeight(0), // Will be filled in when included in block
            proof,
        };

        debug!(
            loser_tx = %loser_tx,
            winner_tx = %winner_tx,
            has_proof = deferral.has_proof(),
            "Queuing deferral with cycle proof"
        );

        self.pending_deferrals.push(deferral);
    }

    /// Get pending deferrals for block inclusion.
    ///
    /// Returns a clone of the pending deferrals. Deferrals are only removed
    /// when they appear in a committed block.
    pub fn get_pending_deferrals(&self) -> Vec<TransactionDefer> {
        self.pending_deferrals.clone()
    }

    /// Called when a block is committed.
    ///
    /// Processes deferrals, aborts, and certificates to clean up tracking state.
    pub fn on_block_committed(&mut self, block: &hyperscale_types::Block) {
        let height = block.header.height;

        // Process committed deferrals
        for deferral in &block.deferred {
            self.on_deferral_committed(&deferral.tx_hash);
        }

        // Process committed aborts
        for abort in &block.aborted {
            self.on_abort_committed(&abort.tx_hash);
        }

        // Process committed certificates (transactions completed)
        for cert in &block.committed_certificates {
            self.on_certificate_committed(&cert.transaction_hash);
        }

        // Remove deferrals that were included in this block
        let deferred_hashes: std::collections::HashSet<_> =
            block.deferred.iter().map(|d| d.tx_hash).collect();
        self.pending_deferrals
            .retain(|d| !deferred_hashes.contains(&d.tx_hash));

        trace!(
            height = height.0,
            deferred = block.deferred.len(),
            aborted = block.aborted.len(),
            certificates = block.committed_certificates.len(),
            "Processed block commit for livelock state"
        );
    }

    /// Called when a deferral commits.
    fn on_deferral_committed(&mut self, tx_hash: &Hash) {
        // Add tombstone with TTL
        let expiry = self.now + self.config.tombstone_ttl;
        self.deferred_tombstones.insert(*tx_hash, expiry);

        // Remove from tracking
        self.committed_tracker.remove(tx_hash);
        self.provision_tracker.remove_tx(tx_hash);
        self.commitment_proofs.remove(tx_hash);

        debug!(
            tx = %tx_hash,
            tombstone_expiry = ?expiry,
            "Deferral committed - added tombstone"
        );
    }

    /// Called when an abort commits.
    fn on_abort_committed(&mut self, tx_hash: &Hash) {
        // Remove from tracking (no tombstone needed - abort is terminal)
        self.committed_tracker.remove(tx_hash);
        self.provision_tracker.remove_tx(tx_hash);
        self.commitment_proofs.remove(tx_hash);

        debug!(tx = %tx_hash, "Abort committed - removed from tracking");
    }

    /// Called when a certificate commits.
    fn on_certificate_committed(&mut self, tx_hash: &Hash) {
        // Remove from tracking
        self.committed_tracker.remove(tx_hash);
        self.provision_tracker.remove_tx(tx_hash);
        self.commitment_proofs.remove(tx_hash);

        trace!(tx = %tx_hash, "Certificate committed - removed from tracking");
    }

    /// Cleanup expired tombstones.
    ///
    /// Called periodically by the cleanup timer.
    pub fn cleanup(&mut self) {
        let now = self.now;
        let before = self.deferred_tombstones.len();

        self.deferred_tombstones.retain(|_, expiry| *expiry > now);

        let removed = before - self.deferred_tombstones.len();
        if removed > 0 {
            debug!(
                removed,
                remaining = self.deferred_tombstones.len(),
                "Cleaned up expired tombstones"
            );
        }
    }

    /// Check if a transaction is cross-shard (needs provisions from other shards).
    pub fn is_cross_shard(&self, tx: &RoutableTransaction) -> bool {
        !self.compute_remote_state_needs(tx).shards.is_empty()
    }

    /// Get statistics for metrics.
    pub fn stats(&self) -> LivelockStats {
        LivelockStats {
            pending_deferrals: self.pending_deferrals.len(),
            active_tombstones: self.deferred_tombstones.len(),
            tracked_transactions: self.committed_tracker.len(),
        }
    }
}

/// Statistics from the livelock state machine for metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct LivelockStats {
    /// Number of deferrals queued for next block.
    pub pending_deferrals: usize,
    /// Number of active tombstones (recently deferred transactions).
    pub active_tombstones: usize,
    /// Number of transactions being tracked for cycle detection.
    pub tracked_transactions: usize,
}

impl SubStateMachine for LivelockState {
    fn try_handle(&mut self, event: &Event) -> Option<Vec<Action>> {
        match event {
            // ProvisionQuorumReached is the ONLY entry point for cycle detection.
            // This ensures Byzantine safety - only verified, quorum-reaching provisions
            // can trigger deferrals.
            Event::ProvisionQuorumReached {
                tx_hash,
                source_shard,
                commitment_proof,
            } => {
                self.on_provision_quorum_reached(*tx_hash, *source_shard, commitment_proof);
                Some(vec![])
            }
            Event::BlockCommitted { block, .. } => {
                self.on_block_committed(block);
                Some(vec![])
            }
            Event::CleanupTimer => {
                self.cleanup();
                Some(vec![])
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
        KeyPair, Signature, SignerBitfield, StateEntry, StaticTopology, ValidatorId, ValidatorInfo,
        ValidatorSet,
    };

    fn make_test_topology(local_shard: ShardGroupId) -> Arc<dyn Topology> {
        // Create a simple topology with 3 validators per shard
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

    fn make_test_node_id(id: u8) -> NodeId {
        // Create a simple NodeId from bytes
        let mut bytes = [0u8; 30];
        bytes[0] = id;
        NodeId::from_bytes(&bytes)
    }

    fn make_commitment_proof(tx_hash: Hash, source_shard: ShardGroupId) -> CommitmentProof {
        // Create a commitment proof with no entries (no node overlap possible)
        CommitmentProof::new(
            tx_hash,
            source_shard,
            SignerBitfield::new(3),
            Signature::zero(),
            BlockHeight(1),
            vec![],
        )
    }

    fn make_commitment_proof_with_nodes(
        tx_hash: Hash,
        source_shard: ShardGroupId,
        node_ids: Vec<NodeId>,
    ) -> CommitmentProof {
        // Create a commitment proof with specific nodes
        let entries: Vec<_> = node_ids
            .into_iter()
            .map(|node_id| StateEntry::test_entry(node_id, 0, vec![], None))
            .collect();
        CommitmentProof::new(
            tx_hash,
            source_shard,
            SignerBitfield::new(3),
            Signature::zero(),
            BlockHeight(1),
            entries,
        )
    }

    fn make_remote_state_needs(
        shards: &[ShardGroupId],
        nodes_by_shard: Vec<(ShardGroupId, Vec<NodeId>)>,
    ) -> RemoteStateNeeds {
        RemoteStateNeeds {
            shards: shards.iter().copied().collect(),
            nodes_by_shard: nodes_by_shard
                .into_iter()
                .map(|(s, nodes)| (s, nodes.into_iter().collect()))
                .collect(),
        }
    }

    // Helper to create a hash with predictable ordering from raw bytes
    fn hash_with_prefix(prefix: u8) -> Hash {
        // Create a hash directly from raw bytes (not blake3 hashed)
        // This gives us predictable ordering: lower prefix = lower hash
        let mut bytes = [0u8; 32];
        bytes[0] = prefix;
        Hash::from_hash_bytes(&bytes)
    }

    #[test]
    fn test_cycle_detection_basic() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut state = LivelockState::new(ShardGroupId(0), topology);

        // Create hashes with predictable ordering
        // local_tx has higher first byte (0xFF) so it loses
        // remote_tx has lower first byte (0x00) so it wins
        let local_tx = hash_with_prefix(0xFF); // Higher hash (will lose)
        let remote_tx = hash_with_prefix(0x00); // Lower hash (will win)

        // Create a node that both transactions will conflict on
        let conflicting_node = make_test_node_id(42);

        // Register local TX as committed needing shard 1's state for the conflicting node
        let needs = make_remote_state_needs(
            &[ShardGroupId(1)],
            vec![(ShardGroupId(1), vec![conflicting_node])],
        );
        state.committed_tracker.add(local_tx, needs);

        // Receive quorum of provisions from shard 1 for remote_tx with the SAME conflicting node
        // This simulates shard 1 having committed a TX that also uses the conflicting node
        let proof =
            make_commitment_proof_with_nodes(remote_tx, ShardGroupId(1), vec![conflicting_node]);
        state.on_provision_quorum_reached(remote_tx, ShardGroupId(1), &proof);

        // Should have queued a deferral (local_tx loses to remote_tx)
        let deferrals = state.get_pending_deferrals();
        assert_eq!(deferrals.len(), 1);
        assert_eq!(deferrals[0].tx_hash, local_tx);

        let DeferReason::LivelockCycle { winner_tx_hash } = &deferrals[0].reason;
        assert_eq!(*winner_tx_hash, remote_tx);
    }

    #[test]
    fn test_no_cycle_when_we_win() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut state = LivelockState::new(ShardGroupId(0), topology);

        // Create hashes with predictable ordering
        // local_tx has lower first byte (0x00) so it wins
        // remote_tx has higher first byte (0xFF) so it loses
        let local_tx = hash_with_prefix(0x00); // Lower hash (will win)
        let remote_tx = hash_with_prefix(0xFF); // Higher hash (will lose)

        // Create a conflicting node
        let conflicting_node = make_test_node_id(42);

        // Register local TX as committed needing shard 1 for the conflicting node
        let needs = make_remote_state_needs(
            &[ShardGroupId(1)],
            vec![(ShardGroupId(1), vec![conflicting_node])],
        );
        state.committed_tracker.add(local_tx, needs);

        // Receive quorum of provisions from shard 1 for remote_tx with overlapping node
        let proof =
            make_commitment_proof_with_nodes(remote_tx, ShardGroupId(1), vec![conflicting_node]);
        state.on_provision_quorum_reached(remote_tx, ShardGroupId(1), &proof);

        // Should NOT have queued a deferral (we win, remote should defer)
        assert!(state.get_pending_deferrals().is_empty());
    }

    #[test]
    fn test_no_cycle_when_no_node_overlap() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut state = LivelockState::new(ShardGroupId(0), topology);

        // local_tx would lose by hash comparison
        let local_tx = hash_with_prefix(0xFF);
        let remote_tx = hash_with_prefix(0x00);

        // Different nodes - no conflict!
        let local_node = make_test_node_id(1);
        let remote_node = make_test_node_id(2);

        // Register local TX as committed needing shard 1 for local_node
        let needs = make_remote_state_needs(
            &[ShardGroupId(1)],
            vec![(ShardGroupId(1), vec![local_node])],
        );
        state.committed_tracker.add(local_tx, needs);

        // Receive quorum of provisions from shard 1 for remote_tx with DIFFERENT node
        let proof = make_commitment_proof_with_nodes(remote_tx, ShardGroupId(1), vec![remote_node]);
        state.on_provision_quorum_reached(remote_tx, ShardGroupId(1), &proof);

        // Should NOT have queued a deferral - no node overlap means no real conflict
        assert!(state.get_pending_deferrals().is_empty());
    }

    #[test]
    fn test_tombstone_filters_late_provisions() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut state = LivelockState::new(ShardGroupId(0), topology);

        let tx = Hash::from_bytes(b"deferred_tx");

        // Add tombstone for a deferred TX
        state
            .deferred_tombstones
            .insert(tx, Duration::from_secs(100));

        // Receive quorum of provisions for the deferred TX
        let proof = make_commitment_proof(tx, ShardGroupId(1));
        state.on_provision_quorum_reached(tx, ShardGroupId(1), &proof);

        // Should not have added to provision tracker (tombstone filtered)
        assert!(!state.provision_tracker.has_provision(tx, ShardGroupId(1)));
    }

    #[test]
    fn test_cleanup_expired_tombstones() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut state = LivelockState::new(ShardGroupId(0), topology);

        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");

        // Add tombstones with different expiry times
        state
            .deferred_tombstones
            .insert(tx1, Duration::from_secs(10));
        state
            .deferred_tombstones
            .insert(tx2, Duration::from_secs(100));

        // Set current time past first expiry
        state.now = Duration::from_secs(50);
        state.cleanup();

        // tx1 should be cleaned up, tx2 should remain
        assert!(!state.deferred_tombstones.contains_key(&tx1));
        assert!(state.deferred_tombstones.contains_key(&tx2));
    }

    #[test]
    fn test_pending_deferral_deduplication() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut state = LivelockState::new(ShardGroupId(0), topology);

        // Create hashes with predictable ordering
        let local_tx = hash_with_prefix(0xFF); // Higher hash (will lose)
        let remote_tx = hash_with_prefix(0x00); // Lower hash (will win)

        let conflicting_node = make_test_node_id(42);

        // Register local TX as committed needing shard 1
        let needs = make_remote_state_needs(
            &[ShardGroupId(1)],
            vec![(ShardGroupId(1), vec![conflicting_node])],
        );
        state.committed_tracker.add(local_tx, needs);

        // Receive quorum of provisions - should queue deferral
        let proof =
            make_commitment_proof_with_nodes(remote_tx, ShardGroupId(1), vec![conflicting_node]);
        state.on_provision_quorum_reached(remote_tx, ShardGroupId(1), &proof);

        assert_eq!(state.get_pending_deferrals().len(), 1);

        // Receive same quorum again - should NOT queue duplicate deferral
        state.on_provision_quorum_reached(remote_tx, ShardGroupId(1), &proof);

        assert_eq!(
            state.get_pending_deferrals().len(),
            1,
            "Should not queue duplicate deferral"
        );

        // Receive quorum from different shard for same cycle - still no duplicate
        let proof2 =
            make_commitment_proof_with_nodes(remote_tx, ShardGroupId(2), vec![conflicting_node]);
        state.on_provision_quorum_reached(remote_tx, ShardGroupId(2), &proof2);

        assert_eq!(
            state.get_pending_deferrals().len(),
            1,
            "Should still have only one deferral for same tx"
        );
    }

    #[test]
    fn test_committed_tracker_cleanup_on_deferral() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut state = LivelockState::new(ShardGroupId(0), topology);

        let tx = hash_with_prefix(0xFF);
        let node = make_test_node_id(1);

        // Register TX as committed
        let needs =
            make_remote_state_needs(&[ShardGroupId(1)], vec![(ShardGroupId(1), vec![node])]);
        state.committed_tracker.add(tx, needs);

        assert!(state.committed_tracker.contains(&tx));

        // Simulate deferral being committed in a block
        let deferral = TransactionDefer {
            tx_hash: tx,
            reason: DeferReason::LivelockCycle {
                winner_tx_hash: hash_with_prefix(0x00),
            },
            block_height: BlockHeight(5),
            proof: None,
        };

        let block = hyperscale_types::Block {
            header: hyperscale_types::BlockHeader {
                height: BlockHeight(5),
                parent_hash: Hash::from_bytes(b"parent"),
                parent_qc: hyperscale_types::QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: 1234567890,
                round: 0,
                is_fallback: false,
            },
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            committed_certificates: vec![],
            deferred: vec![deferral],
            aborted: vec![],
            commitment_proofs: std::collections::HashMap::new(),
        };

        state.on_block_committed(&block);

        // TX should be removed from committed tracker
        assert!(
            !state.committed_tracker.contains(&tx),
            "Deferred TX should be removed from committed tracker"
        );

        // Tombstone should be added
        assert!(
            state.deferred_tombstones.contains_key(&tx),
            "Tombstone should be added for deferred TX"
        );
    }

    #[test]
    fn test_committed_tracker_cleanup_on_certificate() {
        let topology = make_test_topology(ShardGroupId(0));
        let mut state = LivelockState::new(ShardGroupId(0), topology);

        let tx = hash_with_prefix(0xAA);
        let node = make_test_node_id(1);

        // Register TX as committed
        let needs =
            make_remote_state_needs(&[ShardGroupId(1)], vec![(ShardGroupId(1), vec![node])]);
        state.committed_tracker.add(tx, needs);

        assert!(state.committed_tracker.contains(&tx));

        // Simulate certificate being committed (TX completed successfully)
        let cert = hyperscale_types::TransactionCertificate {
            transaction_hash: tx,
            decision: hyperscale_types::TransactionDecision::Accept,
            shard_proofs: std::collections::BTreeMap::new(),
        };

        let block = hyperscale_types::Block {
            header: hyperscale_types::BlockHeader {
                height: BlockHeight(5),
                parent_hash: Hash::from_bytes(b"parent"),
                parent_qc: hyperscale_types::QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: 1234567890,
                round: 0,
                is_fallback: false,
            },
            retry_transactions: vec![],
            priority_transactions: vec![],
            transactions: vec![],
            committed_certificates: vec![std::sync::Arc::new(cert)],
            deferred: vec![],
            aborted: vec![],
            commitment_proofs: std::collections::HashMap::new(),
        };

        state.on_block_committed(&block);

        // TX should be removed from committed tracker (completed successfully)
        assert!(
            !state.committed_tracker.contains(&tx),
            "Completed TX should be removed from committed tracker"
        );
    }

    #[test]
    fn test_no_false_positive_unidirectional() {
        // Test that unidirectional dependencies don't trigger cycle detection
        let topology = make_test_topology(ShardGroupId(0));
        let mut state = LivelockState::new(ShardGroupId(0), topology);

        let local_tx = hash_with_prefix(0xFF);
        let remote_tx = hash_with_prefix(0x00);

        let node1 = make_test_node_id(1);
        let node2 = make_test_node_id(2);

        // Local TX needs shard 1, but shard 1's TX does NOT need us
        let needs =
            make_remote_state_needs(&[ShardGroupId(1)], vec![(ShardGroupId(1), vec![node1])]);
        state.committed_tracker.add(local_tx, needs);

        // Receive quorum from shard 2 (not shard 1) for remote_tx
        // This means remote_tx needs our state, but we don't need shard 2's state
        // so there's no cycle with our local_tx
        let proof = make_commitment_proof_with_nodes(remote_tx, ShardGroupId(2), vec![node2]);
        state.on_provision_quorum_reached(remote_tx, ShardGroupId(2), &proof);

        // Should NOT queue a deferral - no cycle exists
        // Our local_tx needs shard 1, provision is from shard 2
        assert!(
            state.get_pending_deferrals().is_empty(),
            "Unidirectional dependency should not cause deferral"
        );
    }
}
