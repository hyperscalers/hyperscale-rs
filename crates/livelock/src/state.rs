//! LivelockState sub-state machine for cycle detection and abort intent management.
//!
//! This module implements the provision-based cycle detection system that
//! prevents bidirectional livelock in cross-shard transactions.

use crate::tracker::{CommittedCrossShardTracker, ProvisionTracker, RemoteStateNeeds};
use hyperscale_core::{Action, InclusionProofFetchReason};
use hyperscale_types::{
    AbortIntent, AbortReason, BlockHeight, Hash, NodeId, RoutableTransaction, ShardGroupId,
    StateEntry, TopologySnapshot, TransactionInclusionProof,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, trace};

/// Output produced by the livelock state machine when a cycle is detected.
///
/// The caller must fetch the inclusion proof from the source shard and then
/// call `on_inclusion_proof_received` to complete the abort intent queuing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LivelockOutput {
    /// A cycle was detected; fetch the merkle inclusion proof for the winner TX
    /// from its source shard before we can queue the abort intent.
    FetchInclusionProof {
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        winner_tx_hash: Hash,
        loser_tx_hash: Hash,
    },
}

/// Configuration for livelock prevention.
#[derive(Debug, Clone)]
pub struct LivelockConfig {
    /// How long to keep tombstones for completed transactions.
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
    /// Tracks committed cross-shard TXs and which shards they need provisions from.
    committed_tracker: CommittedCrossShardTracker,

    /// Tracks provisions received: (tx_hash, source_shard) pairs.
    /// Used for both early detection and deduplication.
    provision_tracker: ProvisionTracker,

    /// Tombstones for completed transactions to discard late-arriving provisions.
    /// Maps tx_hash -> tombstone expiry time.
    /// Added when any terminal state COMMITS (certificate, abort, or deferral).
    tombstones: HashMap<Hash, Duration>,

    /// Loser tx hashes for which we've requested inclusion proofs but
    /// haven't received them yet.
    pending_proof_fetches: HashSet<Hash>,

    /// Abort intents ready to be included in next block proposal.
    /// Kept until they appear in a committed block.
    pending_abort_intents: Vec<AbortIntent>,

    /// Hash set tracking queued abort intent tx_hashes for deduplication.
    pending_abort_intent_hashes: HashSet<Hash>,

    /// Current time.
    now: Duration,

    /// Configuration.
    config: LivelockConfig,
}

impl std::fmt::Debug for LivelockState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LivelockState")
            .field("committed_tracker_len", &self.committed_tracker.len())
            .field("provision_tracker_len", &self.provision_tracker.len())
            .field("tombstones_len", &self.tombstones.len())
            .field(
                "pending_abort_intents_len",
                &self.pending_abort_intents.len(),
            )
            .finish()
    }
}

impl Default for LivelockState {
    fn default() -> Self {
        Self::new()
    }
}

impl LivelockState {
    /// Create a new LivelockState.
    pub fn new() -> Self {
        Self::with_config(LivelockConfig::default())
    }

    /// Create a new LivelockState with custom configuration.
    pub fn with_config(config: LivelockConfig) -> Self {
        Self {
            committed_tracker: CommittedCrossShardTracker::new(),
            provision_tracker: ProvisionTracker::new(),
            tombstones: HashMap::new(),
            pending_proof_fetches: HashSet::new(),
            pending_abort_intents: Vec::new(),
            pending_abort_intent_hashes: HashSet::new(),
            now: Duration::ZERO,
            config,
        }
    }

    /// Set the current time.
    pub fn set_time(&mut self, now: Duration) {
        self.now = now;
    }

    /// Compute which remote shards and nodes a transaction needs provisions from.
    fn compute_remote_state_needs(
        &self,
        topology: &TopologySnapshot,
        tx: &RoutableTransaction,
    ) -> RemoteStateNeeds {
        let local_shard = topology.local_shard();

        // Collect all reads and writes, grouped by shard
        let mut nodes_by_shard: HashMap<ShardGroupId, HashSet<NodeId>> = HashMap::new();

        // Add read nodes (provisions come from read shards)
        for node_id in &tx.declared_reads {
            let shard = topology.shard_for_node_id(node_id);
            if shard != local_shard {
                nodes_by_shard.entry(shard).or_default().insert(*node_id);
            }
        }

        // Add write nodes from remote shards (for read-your-writes scenarios)
        for node_id in &tx.declared_writes {
            let shard = topology.shard_for_node_id(node_id);
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
    /// This method only processes provisions that have been verified (QC + merkle
    /// proofs). This prevents Byzantine validators from triggering false deferrals
    /// with forged provisions.
    ///
    /// Returns [`LivelockOutput::FetchInclusionProof`] entries for each cycle
    /// detected. The caller must fetch the proof and call
    /// [`on_inclusion_proof_received`] to finalize the deferral.
    ///
    /// # Arguments
    /// * `remote_tx_hash` - The remote transaction's hash
    /// * `source_shard` - The shard that sent the verified provision
    /// * `source_block_height` - The block height on the source shard
    /// * `entries` - The state entries from the remote transaction (used transiently for node-ID extraction)
    pub fn on_provision_accepted(
        &mut self,
        remote_tx_hash: Hash,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        entries: &[StateEntry],
    ) -> Vec<LivelockOutput> {
        trace!(
            remote_tx = %remote_tx_hash,
            source_shard = source_shard.0,
            entries = entries.len(),
            "Processing verified provision for cycle detection"
        );

        // Check tombstone - discard late provisions for deferred TXs
        if self.tombstones.contains_key(&remote_tx_hash) {
            trace!(
                remote_tx = %remote_tx_hash,
                "Discarding quorum - TX has tombstone (already completed)"
            );
            return vec![];
        }

        // Check if we've already processed this (tx, shard) for cycle detection
        if !self.provision_tracker.add(remote_tx_hash, source_shard) {
            return vec![];
        }

        // Get nodes from the entries (transient — not stored)
        let remote_tx_nodes: HashSet<NodeId> = entries.iter().filter_map(|e| e.node_id()).collect();

        // Check for cycle with our local committed TXs
        self.check_for_cycle(
            remote_tx_hash,
            source_shard,
            source_block_height,
            &remote_tx_nodes,
        )
    }

    /// Process a batch of verified provisions for cycle detection.
    ///
    /// Equivalent to calling [`on_provision_accepted`] for each transaction in the
    /// batch, returning all outputs combined.
    pub fn on_provisions_accepted(
        &mut self,
        batch: &hyperscale_types::ProvisionBatch,
    ) -> Vec<LivelockOutput> {
        let mut outputs = Vec::new();
        for tx_entries in &batch.transactions {
            outputs.extend(self.on_provision_accepted(
                tx_entries.tx_hash,
                batch.source_shard,
                batch.block_height,
                &tx_entries.entries,
            ));
        }
        outputs
    }

    /// Process verified provisions and return network actions for inclusion proof fetches.
    ///
    /// Combines cycle detection with action construction: groups deferral proof
    /// requests by (source_shard, block_height) and enriches with topology peers.
    pub fn on_provisions_accepted_actions(
        &mut self,
        batch: &hyperscale_types::ProvisionBatch,
        topology: &TopologySnapshot,
    ) -> Vec<Action> {
        let outputs = self.on_provisions_accepted(batch);
        if outputs.is_empty() {
            return vec![];
        }

        // Group deferral proof requests by (source_shard, block_height).
        let mut grouped: BTreeMap<
            (ShardGroupId, BlockHeight),
            Vec<(Hash, InclusionProofFetchReason)>,
        > = BTreeMap::new();
        for output in outputs {
            match output {
                LivelockOutput::FetchInclusionProof {
                    source_shard,
                    source_block_height,
                    winner_tx_hash,
                    loser_tx_hash,
                } => {
                    grouped
                        .entry((source_shard, source_block_height))
                        .or_default()
                        .push((
                            winner_tx_hash,
                            InclusionProofFetchReason::Deferral { loser_tx_hash },
                        ));
                }
            }
        }

        grouped
            .into_iter()
            .map(|((source_shard, source_block_height), entries)| {
                let peers = topology.committee_for_shard(source_shard).to_vec();
                Action::RequestTxInclusionProofs {
                    source_shard,
                    source_block_height,
                    entries,
                    peers,
                }
            })
            .collect()
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
        source_block_height: BlockHeight,
        remote_tx_nodes: &HashSet<NodeId>,
    ) -> Vec<LivelockOutput> {
        // Get all our committed TXs that need provisions from the remote shard
        let Some(local_txs_needing_source) = self.committed_tracker.txs_needing_shard(source_shard)
        else {
            return vec![];
        };

        // Collect outputs
        let mut outputs: Vec<LivelockOutput> = Vec::new();

        // For each local TX that needs the source shard...
        for &local_tx_hash in local_txs_needing_source {
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
            let has_overlap = !local_nodes_needed.is_disjoint(remote_tx_nodes);

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
                    "TRUE cycle detected with overlapping nodes - requesting inclusion proof"
                );

                // Don't queue the abort intent yet — we need the inclusion proof first.
                // Track that we have an in-flight fetch for this loser.
                if !self.pending_abort_intent_hashes.contains(&loser)
                    && !self.pending_proof_fetches.contains(&loser)
                {
                    self.pending_proof_fetches.insert(loser);
                    outputs.push(LivelockOutput::FetchInclusionProof {
                        source_shard,
                        source_block_height,
                        winner_tx_hash: winner,
                        loser_tx_hash: loser,
                    });
                }
            } else {
                debug!(
                    local_tx = %local_tx_hash,
                    remote_tx = %remote_tx_hash,
                    winner = %winner,
                    "Cycle detected - our TX wins, remote TX should defer"
                );
            }
        }

        outputs
    }

    /// Called when the inclusion proof for a winner transaction has been fetched.
    ///
    /// Completes the two-phase abort intent: the proof is attached to the
    /// `AbortIntent` which is then queued for block inclusion.
    pub fn on_inclusion_proof_received(
        &mut self,
        winner_tx_hash: Hash,
        loser_tx_hash: Hash,
        proof: TransactionInclusionProof,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
    ) {
        self.pending_proof_fetches.remove(&loser_tx_hash);
        self.queue_abort_intent(
            loser_tx_hash,
            winner_tx_hash,
            source_shard,
            source_block_height,
            proof,
        );
    }

    /// Queue an abort intent for inclusion in the next block.
    ///
    /// The abort intent carries a merkle inclusion proof for the winner transaction.
    /// BFT validation rejects abort intents without valid proofs.
    fn queue_abort_intent(
        &mut self,
        loser_tx: Hash,
        winner_tx: Hash,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        proof: TransactionInclusionProof,
    ) {
        // Check if already queued
        if self.pending_abort_intent_hashes.contains(&loser_tx) {
            trace!(tx = %loser_tx, "Abort intent already queued");
            return;
        }

        let abort_intent = AbortIntent {
            tx_hash: loser_tx,
            reason: AbortReason::LivelockCycle {
                winner_tx_hash: winner_tx,
                source_shard,
                source_block_height,
                tx_inclusion_proof: proof,
            },
            block_height: BlockHeight(0), // Will be filled in when included in block
        };

        debug!(
            loser_tx = %loser_tx,
            winner_tx = %winner_tx,
            source_shard = source_shard.0,
            "Queuing abort intent with inclusion proof"
        );

        self.pending_abort_intent_hashes.insert(loser_tx);
        self.pending_abort_intents.push(abort_intent);
    }

    /// Get pending abort intents for block inclusion.
    ///
    /// Returns a reference to the pending abort intents. Abort intents are only
    /// removed when they appear in a committed block or are explicitly purged
    /// via [`remove_abort_intents`].
    pub fn get_pending_abort_intents(&self) -> &[AbortIntent] {
        &self.pending_abort_intents
    }

    /// Remove expired tombstones. Called during block commit to prevent unbounded growth.
    fn cleanup_tombstones(&mut self) {
        let now = self.now;
        let before = self.tombstones.len();
        self.tombstones.retain(|_, &mut expiry| expiry > now);
        let pruned = before - self.tombstones.len();
        if pruned > 0 {
            tracing::debug!(pruned, remaining = self.tombstones.len(), "Pruned expired livelock tombstones");
        }
    }

    /// Called when a block is committed.
    ///
    /// First registers any cross-shard transactions for cycle detection,
    /// then processes abort intents and certificates to clean up tracking state.
    /// The registration must happen before processing to maintain ordering invariants.
    pub fn on_block_committed(
        &mut self,
        topology: &TopologySnapshot,
        block: &hyperscale_types::Block,
    ) {
        let height = block.header.height;

        // Register newly committed cross-shard TXs for cycle detection.
        // Must happen BEFORE processing abort intents/certificates below.
        for tx in block.transactions.iter() {
            let needs = self.compute_remote_state_needs(topology, tx);
            if !needs.shards.is_empty() {
                let tx_hash = tx.hash();
                debug!(
                    tx_hash = %tx_hash,
                    height = height.0,
                    shards = ?needs.shards,
                    "Tracking committed cross-shard TX for cycle detection"
                );
                self.committed_tracker.add(tx_hash, needs);
            }
        }

        // Process committed abort intents (covers both livelock deferrals and timeouts)
        for intent in &block.abort_intents {
            self.on_abort_intent_committed(&intent.tx_hash);
        }

        // NOTE: Certificate-committed cleanup (tombstones, tracker removal) is NOT
        // done here. Wave certificates are lean — they don't carry per-tx hashes.
        // The node state machine calls on_certificate_committed() per tx_hash after
        // extracting decisions from FinalizedWave data.

        // Remove abort intents that were included in this block from both Vec and HashSet
        for intent in &block.abort_intents {
            self.pending_abort_intent_hashes.remove(&intent.tx_hash);
        }

        // Also remove pending abort intents whose winner transaction was aborted in this block.
        // If the winner is gone, the abort intent can never complete (the loser was
        // waiting for the winner to finish). The mempool handles creating a retry
        // via on_winner_aborted; we just need to stop proposing the stale intent.
        {
            let aborted_hashes: std::collections::HashSet<_> =
                block.abort_intents.iter().map(|a| a.tx_hash).collect();
            let mut removed_for_winner_abort = Vec::new();
            for intent in &self.pending_abort_intents {
                if let AbortReason::LivelockCycle { winner_tx_hash, .. } = &intent.reason {
                    if aborted_hashes.contains(winner_tx_hash) {
                        removed_for_winner_abort.push(intent.tx_hash);
                        tracing::info!(
                            loser = %intent.tx_hash,
                            winner = %winner_tx_hash,
                            "Removed pending abort intent: winner was aborted"
                        );
                    }
                }
            }
            for tx_hash in &removed_for_winner_abort {
                self.pending_abort_intent_hashes.remove(tx_hash);
            }
        }

        // Keep only abort intents still in our hash set (those not in this block)
        self.pending_abort_intents
            .retain(|d| self.pending_abort_intent_hashes.contains(&d.tx_hash));

        // Prune expired tombstones to prevent unbounded growth.
        self.cleanup_tombstones();

        trace!(
            height = height.0,
            abort_intents = block.abort_intents.len(),
            certificates = block.certificates.len(),
            "Processed block commit for livelock state"
        );
    }

    /// Called when an abort intent commits.
    fn on_abort_intent_committed(&mut self, tx_hash: &Hash) {
        // Add tombstone with TTL
        let expiry = self.now + self.config.tombstone_ttl;
        self.tombstones.insert(*tx_hash, expiry);

        // Remove from tracking
        self.committed_tracker.remove(tx_hash);
        self.provision_tracker.remove_tx(tx_hash);
        self.pending_proof_fetches.remove(tx_hash);

        debug!(
            tx = %tx_hash,
            tombstone_expiry = ?expiry,
            "Abort intent committed - added tombstone"
        );
    }

    /// Called when a certificate commits.
    pub fn on_certificate_committed(&mut self, tx_hash: &Hash) {
        // Add tombstone to prevent late provisions from re-populating state
        let expiry = self.now + self.config.tombstone_ttl;
        self.tombstones.insert(*tx_hash, expiry);

        // Remove from tracking
        self.committed_tracker.remove(tx_hash);
        self.provision_tracker.remove_tx(tx_hash);
        self.pending_proof_fetches.remove(tx_hash);

        // Remove pending abort intents for this transaction — once the certificate
        // commits, the abort is moot.
        self.pending_abort_intent_hashes.remove(tx_hash);

        trace!(tx = %tx_hash, "Certificate committed - added tombstone");
    }

    /// Cleanup expired tombstones.
    ///
    /// Called periodically by the cleanup timer.
    pub fn cleanup(&mut self) {
        let now = self.now;
        let before = self.tombstones.len();

        self.tombstones.retain(|_, expiry| *expiry > now);

        let removed = before - self.tombstones.len();
        if removed > 0 {
            debug!(
                removed,
                remaining = self.tombstones.len(),
                "Cleaned up expired tombstones"
            );
        }
    }

    /// Get statistics for metrics.
    pub fn stats(&self) -> LivelockStats {
        LivelockStats {
            pending_abort_intents: self.pending_abort_intents.len(),
            active_tombstones: self.tombstones.len(),
            tracked_transactions: self.committed_tracker.len(),
            pending_proof_fetches: self.pending_proof_fetches.len(),
        }
    }
}

/// Statistics from the livelock state machine for metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct LivelockStats {
    /// Number of abort intents queued for next block.
    pub pending_abort_intents: usize,
    /// Number of active tombstones (recently completed transactions).
    pub active_tombstones: usize,
    /// Number of transactions being tracked for cycle detection.
    pub tracked_transactions: usize,
    /// Number of loser transactions awaiting inclusion proof fetch.
    pub pending_proof_fetches: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperscale_types::{
        AbortReason, TransactionInclusionProof, ValidatorId, ValidatorInfo, ValidatorSet,
    };

    fn make_test_topology() -> TopologySnapshot {
        let key = hyperscale_types::Bls12381G1PrivateKey::from_u64(1).unwrap();
        let validators = vec![ValidatorInfo {
            validator_id: ValidatorId(0),
            public_key: key.public_key(),
            voting_power: 1,
        }];
        TopologySnapshot::new(ValidatorId(0), 1, ValidatorSet::new(validators))
    }

    fn make_test_node_id(id: u8) -> NodeId {
        // Create a simple NodeId from bytes
        let mut bytes = [0u8; 30];
        bytes[0] = id;
        NodeId::from_bytes(&bytes)
    }

    fn make_test_entries_with_nodes(node_ids: Vec<NodeId>) -> Vec<StateEntry> {
        node_ids
            .into_iter()
            .map(|node_id| StateEntry::test_entry(node_id, 0, vec![], None))
            .collect()
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

    fn dummy_proof() -> TransactionInclusionProof {
        TransactionInclusionProof {
            siblings: vec![],
            leaf_index: 0,
        }
    }

    /// Helper: call on_provision_accepted and, if a FetchInclusionProof output
    /// is returned for the expected loser, simulate receiving the proof so
    /// the deferral gets queued (completing the two-phase flow).
    fn accept_and_complete_deferral(
        state: &mut LivelockState,
        remote_tx_hash: Hash,
        source_shard: ShardGroupId,
        source_block_height: BlockHeight,
        entries: &[StateEntry],
    ) -> Vec<LivelockOutput> {
        let outputs =
            state.on_provision_accepted(remote_tx_hash, source_shard, source_block_height, entries);
        for output in &outputs {
            match output {
                LivelockOutput::FetchInclusionProof {
                    source_shard,
                    source_block_height,
                    winner_tx_hash,
                    loser_tx_hash,
                } => {
                    state.on_inclusion_proof_received(
                        *winner_tx_hash,
                        *loser_tx_hash,
                        dummy_proof(),
                        *source_shard,
                        *source_block_height,
                    );
                }
            }
        }
        outputs
    }

    fn make_test_abort_intent(loser: Hash, winner: Hash) -> AbortIntent {
        AbortIntent {
            tx_hash: loser,
            reason: AbortReason::LivelockCycle {
                winner_tx_hash: winner,
                source_shard: ShardGroupId(1),
                source_block_height: BlockHeight(1),
                tx_inclusion_proof: dummy_proof(),
            },
            block_height: BlockHeight(5),
        }
    }

    #[test]
    fn test_cycle_detection_basic() {
        let mut state = LivelockState::new();

        let local_tx = hash_with_prefix(0xFF); // Higher hash (will lose)
        let remote_tx = hash_with_prefix(0x00); // Lower hash (will win)

        let conflicting_node = make_test_node_id(42);

        let needs = make_remote_state_needs(
            &[ShardGroupId(1)],
            vec![(ShardGroupId(1), vec![conflicting_node])],
        );
        state.committed_tracker.add(local_tx, needs);

        let entries = make_test_entries_with_nodes(vec![conflicting_node]);
        let outputs =
            state.on_provision_accepted(remote_tx, ShardGroupId(1), BlockHeight(1), &entries);

        // Phase 1: should request inclusion proof
        assert_eq!(outputs.len(), 1);
        match &outputs[0] {
            LivelockOutput::FetchInclusionProof {
                winner_tx_hash,
                loser_tx_hash,
                ..
            } => {
                assert_eq!(*winner_tx_hash, remote_tx);
                assert_eq!(*loser_tx_hash, local_tx);
            }
        }

        // No abort intent queued yet
        assert!(state.get_pending_abort_intents().is_empty());

        // Phase 2: simulate proof received
        state.on_inclusion_proof_received(
            remote_tx,
            local_tx,
            dummy_proof(),
            ShardGroupId(1),
            BlockHeight(1),
        );

        // Now the abort intent should be queued
        let abort_intents = state.get_pending_abort_intents();
        assert_eq!(abort_intents.len(), 1);
        assert_eq!(abort_intents[0].tx_hash, local_tx);

        let AbortReason::LivelockCycle { winner_tx_hash, .. } = &abort_intents[0].reason else {
            panic!("Expected LivelockCycle reason");
        };
        assert_eq!(*winner_tx_hash, remote_tx);
    }

    #[test]
    fn test_no_cycle_when_we_win() {
        let mut state = LivelockState::new();

        let local_tx = hash_with_prefix(0x00); // Lower hash (will win)
        let remote_tx = hash_with_prefix(0xFF); // Higher hash (will lose)

        let conflicting_node = make_test_node_id(42);

        let needs = make_remote_state_needs(
            &[ShardGroupId(1)],
            vec![(ShardGroupId(1), vec![conflicting_node])],
        );
        state.committed_tracker.add(local_tx, needs);

        let entries = make_test_entries_with_nodes(vec![conflicting_node]);
        let outputs =
            state.on_provision_accepted(remote_tx, ShardGroupId(1), BlockHeight(1), &entries);

        assert!(outputs.is_empty());
        assert!(state.get_pending_abort_intents().is_empty());
    }

    #[test]
    fn test_no_cycle_when_no_node_overlap() {
        let mut state = LivelockState::new();

        let local_tx = hash_with_prefix(0xFF);
        let remote_tx = hash_with_prefix(0x00);

        let local_node = make_test_node_id(1);
        let remote_node = make_test_node_id(2);

        let needs = make_remote_state_needs(
            &[ShardGroupId(1)],
            vec![(ShardGroupId(1), vec![local_node])],
        );
        state.committed_tracker.add(local_tx, needs);

        let entries = make_test_entries_with_nodes(vec![remote_node]);
        let outputs =
            state.on_provision_accepted(remote_tx, ShardGroupId(1), BlockHeight(1), &entries);

        assert!(outputs.is_empty());
        assert!(state.get_pending_abort_intents().is_empty());
    }

    #[test]
    fn test_tombstone_filters_late_provisions() {
        let mut state = LivelockState::new();

        let tx = Hash::from_bytes(b"deferred_tx");

        // Add tombstone for a deferred TX
        state.tombstones.insert(tx, Duration::from_secs(100));

        // Receive quorum of provisions for the deferred TX
        let entries: Vec<StateEntry> = vec![];
        let outputs = state.on_provision_accepted(tx, ShardGroupId(1), BlockHeight(1), &entries);

        assert!(outputs.is_empty());
        // Should not have added to provision tracker (tombstone filtered)
        assert!(!state.provision_tracker.has_provision(tx, ShardGroupId(1)));
    }

    #[test]
    fn test_cleanup_expired_tombstones() {
        let mut state = LivelockState::new();

        let tx1 = Hash::from_bytes(b"tx1");
        let tx2 = Hash::from_bytes(b"tx2");

        // Add tombstones with different expiry times
        state.tombstones.insert(tx1, Duration::from_secs(10));
        state.tombstones.insert(tx2, Duration::from_secs(100));

        // Set current time past first expiry
        state.now = Duration::from_secs(50);
        state.cleanup();

        // tx1 should be cleaned up, tx2 should remain
        assert!(!state.tombstones.contains_key(&tx1));
        assert!(state.tombstones.contains_key(&tx2));
    }

    #[test]
    fn test_pending_deferral_deduplication() {
        let mut state = LivelockState::new();

        let local_tx = hash_with_prefix(0xFF); // Higher hash (will lose)
        let remote_tx = hash_with_prefix(0x00); // Lower hash (will win)

        let conflicting_node = make_test_node_id(42);

        let needs = make_remote_state_needs(
            &[ShardGroupId(1)],
            vec![(ShardGroupId(1), vec![conflicting_node])],
        );
        state.committed_tracker.add(local_tx, needs);

        // Receive quorum of provisions - should trigger fetch + deferral
        let entries = make_test_entries_with_nodes(vec![conflicting_node]);
        accept_and_complete_deferral(
            &mut state,
            remote_tx,
            ShardGroupId(1),
            BlockHeight(1),
            &entries,
        );

        assert_eq!(state.get_pending_abort_intents().len(), 1);

        // Receive same quorum again - should NOT queue duplicate
        let entries = make_test_entries_with_nodes(vec![conflicting_node]);
        let outputs =
            state.on_provision_accepted(remote_tx, ShardGroupId(1), BlockHeight(1), &entries);
        assert!(outputs.is_empty());

        assert_eq!(
            state.get_pending_abort_intents().len(),
            1,
            "Should not queue duplicate abort intent"
        );

        // Receive quorum from different shard for same cycle - still no duplicate
        let entries2 = make_test_entries_with_nodes(vec![conflicting_node]);
        let outputs =
            state.on_provision_accepted(remote_tx, ShardGroupId(2), BlockHeight(1), &entries2);
        assert!(outputs.is_empty());

        assert_eq!(
            state.get_pending_abort_intents().len(),
            1,
            "Should still have only one abort intent for same tx"
        );
    }

    #[test]
    fn test_committed_tracker_cleanup_on_abort_intent() {
        let mut state = LivelockState::new();

        let tx = hash_with_prefix(0xFF);
        let node = make_test_node_id(1);

        let needs =
            make_remote_state_needs(&[ShardGroupId(1)], vec![(ShardGroupId(1), vec![node])]);
        state.committed_tracker.add(tx, needs);

        assert!(state.committed_tracker.contains(&tx));

        let winner = hash_with_prefix(0x00);
        let abort_intent = make_test_abort_intent(tx, winner);

        let block = hyperscale_types::Block {
            header: hyperscale_types::BlockHeader {
                shard_group_id: hyperscale_types::ShardGroupId(0),
                height: BlockHeight(5),
                parent_hash: Hash::from_bytes(b"parent"),
                parent_qc: hyperscale_types::QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: 1234567890,
                round: 0,
                is_fallback: false,
                state_root: Hash::ZERO,
                transaction_root: Hash::ZERO,
                certificate_root: Hash::ZERO,
                local_receipt_root: Hash::ZERO,
                waves: vec![],
            },
            transactions: vec![],
            certificates: vec![],
            abort_intents: vec![abort_intent],
        };

        state.on_block_committed(&make_test_topology(), &block);

        assert!(
            !state.committed_tracker.contains(&tx),
            "TX with committed abort intent should be removed from committed tracker"
        );

        assert!(
            state.tombstones.contains_key(&tx),
            "Tombstone should be added for TX with committed abort intent"
        );
    }

    #[test]
    fn test_committed_tracker_cleanup_on_certificate() {
        let mut state = LivelockState::new();

        let tx = hash_with_prefix(0xAA);
        let node = make_test_node_id(1);

        let needs =
            make_remote_state_needs(&[ShardGroupId(1)], vec![(ShardGroupId(1), vec![node])]);
        state.committed_tracker.add(tx, needs);

        assert!(state.committed_tracker.contains(&tx));

        // Simulate certificate commit for this synthetic tx hash directly.
        state.on_certificate_committed(&tx);

        assert!(
            !state.committed_tracker.contains(&tx),
            "Completed TX should be removed from committed tracker"
        );
    }

    #[test]
    fn test_no_false_positive_unidirectional() {
        let mut state = LivelockState::new();

        let local_tx = hash_with_prefix(0xFF);
        let remote_tx = hash_with_prefix(0x00);

        let node1 = make_test_node_id(1);
        let node2 = make_test_node_id(2);

        let needs =
            make_remote_state_needs(&[ShardGroupId(1)], vec![(ShardGroupId(1), vec![node1])]);
        state.committed_tracker.add(local_tx, needs);

        let entries = make_test_entries_with_nodes(vec![node2]);
        let outputs =
            state.on_provision_accepted(remote_tx, ShardGroupId(2), BlockHeight(1), &entries);

        assert!(outputs.is_empty());
        assert!(
            state.get_pending_abort_intents().is_empty(),
            "Unidirectional dependency should not cause abort intent"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Tombstone Tests (Fix 2: cover completed and aborted txs)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_certificate_commit_adds_tombstone() {
        let mut state = LivelockState::new();

        let tx = hash_with_prefix(0xAA);
        let node = make_test_node_id(1);

        let needs =
            make_remote_state_needs(&[ShardGroupId(1)], vec![(ShardGroupId(1), vec![node])]);
        state.committed_tracker.add(tx, needs);

        // Simulate certificate commit for this synthetic tx hash directly.
        state.on_certificate_committed(&tx);

        assert!(
            state.tombstones.contains_key(&tx),
            "Certificate commit should add tombstone"
        );

        // Late provision should be rejected
        let entries: Vec<StateEntry> = vec![];
        let outputs = state.on_provision_accepted(tx, ShardGroupId(1), BlockHeight(1), &entries);
        assert!(
            outputs.is_empty(),
            "Late provision after certificate should be rejected by tombstone"
        );
    }

    #[test]
    fn test_abort_commit_adds_tombstone() {
        let mut state = LivelockState::new();

        let tx = hash_with_prefix(0xBB);
        let node = make_test_node_id(1);

        let needs =
            make_remote_state_needs(&[ShardGroupId(1)], vec![(ShardGroupId(1), vec![node])]);
        state.committed_tracker.add(tx, needs);

        let abort_intent = hyperscale_types::AbortIntent {
            tx_hash: tx,
            reason: hyperscale_types::AbortReason::ExecutionTimeout {
                committed_at: BlockHeight(1),
            },
            block_height: BlockHeight(5),
        };

        let block = hyperscale_types::Block {
            header: hyperscale_types::BlockHeader {
                shard_group_id: ShardGroupId(0),
                height: BlockHeight(5),
                parent_hash: Hash::from_bytes(b"parent"),
                parent_qc: hyperscale_types::QuorumCertificate::genesis(),
                proposer: ValidatorId(0),
                timestamp: 1234567890,
                round: 0,
                is_fallback: false,
                state_root: Hash::ZERO,
                transaction_root: Hash::ZERO,
                certificate_root: Hash::ZERO,
                local_receipt_root: Hash::ZERO,
                waves: vec![],
            },
            transactions: vec![],
            certificates: vec![],
            abort_intents: vec![abort_intent],
        };

        state.on_block_committed(&make_test_topology(), &block);

        assert!(
            state.tombstones.contains_key(&tx),
            "Abort commit should add tombstone"
        );

        // Late provision should be rejected
        let entries: Vec<StateEntry> = vec![];
        let outputs = state.on_provision_accepted(tx, ShardGroupId(1), BlockHeight(1), &entries);
        assert!(
            outputs.is_empty(),
            "Late provision after abort should be rejected by tombstone"
        );
    }

    #[test]
    fn test_tombstone_cleanup_removes_expired() {
        let config = LivelockConfig {
            tombstone_ttl: Duration::from_secs(30),
            ..Default::default()
        };
        let mut state = LivelockState::with_config(config);

        // Insert tombstones at t=10s (expire at t=40s)
        state.set_time(Duration::from_secs(10));
        let tx1 = hash_with_prefix(1);
        let tx2 = hash_with_prefix(2);
        state.tombstones.insert(tx1, Duration::from_secs(40));
        state.tombstones.insert(tx2, Duration::from_secs(40));

        // Insert a tombstone at t=30s (expires at t=60s)
        let tx3 = hash_with_prefix(3);
        state.tombstones.insert(tx3, Duration::from_secs(60));

        assert_eq!(state.tombstones.len(), 3);

        // Advance to t=50s — tx1 and tx2 should be pruned, tx3 should remain
        state.set_time(Duration::from_secs(50));
        state.cleanup_tombstones();

        assert_eq!(state.tombstones.len(), 1);
        assert!(!state.tombstones.contains_key(&tx1));
        assert!(!state.tombstones.contains_key(&tx2));
        assert!(state.tombstones.contains_key(&tx3));
    }
}
